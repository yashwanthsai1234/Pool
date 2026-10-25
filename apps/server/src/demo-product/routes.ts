// The product demo's routes (build/PRODUCT_DEMO.md 1 to 4), mounted only through the server's demo hook (like the
// walkthrough), so a production process never has them. Deals run one ledger stage at a time across all deals.
// Source: build/PRODUCT_DEMO.md
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { join } from 'node:path';
import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import { type WalkthroughDeps, WalkthroughError } from '../demo-walkthrough/walkthrough.ts';
import { ProductDeal } from './deal.ts';
import { Participants } from './participants.ts';

const PDF_MAX = 5 * 1024 * 1024;

const ParticipantBody = z.strictObject({ name: z.string().trim().min(1).max(80) });
const DealForm = z.strictObject({
  senderRid: z.string(),
  recipientRid: z.string(),
  amountXrp: z.coerce.number().int().min(1).max(1000),
  terms: z.string().max(2000),
});
const ApproveBody = z.strictObject({ rid: z.string(), stage: z.number().int() });

const json = (b: unknown): unknown => {
  try {
    return JSON.parse(Buffer.isBuffer(b) ? b.toString('utf8') : '');
  } catch {
    return undefined;
  }
};

export async function registerProductRoutes(
  app: FastifyInstance,
  deps: WalkthroughDeps & { dataDir: string },
): Promise<void> {
  const people = new Participants(deps.ledgerWs);
  const deals = new Map<string, ProductDeal>();
  const pdfDir = join(deps.dataDir, 'demo-contracts');
  let queue: Promise<unknown> = Promise.resolve();
  const serial = <T>(f: () => Promise<T>): Promise<T> => {
    const run = queue.then(f);
    queue = run.catch(() => undefined);
    return run;
  };
  const answer = async (reply: FastifyReply, f: () => Promise<unknown>) => {
    try {
      return await f();
    } catch (e) {
      if (e instanceof WalkthroughError) return reply.code(e.status).send({ error: e.code, message: e.message });
      return reply.code(500).send({ error: 'product_failed', message: e instanceof Error ? e.message : String(e) });
    }
  };
  const bad = (reply: FastifyReply, message: string) => reply.code(400).send({ error: 'invalid_request', message });
  app.addHook('onClose', async () => {
    await Promise.all([...deals.values()].map((d) => d.close().catch(() => undefined)));
  });
  // Multipart bodies reach the route as bytes; the WHATWG Request parses them.
  // Source: https://fetch.spec.whatwg.org/#dom-body-formdata ; https://fastify.dev/docs/latest/Reference/ContentTypeParser/
  app.addContentTypeParser('multipart/form-data', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));

  app.post('/demo/participants', async (req, reply) => {
    const body = ParticipantBody.safeParse(json(req.body));
    if (!body.success) return bad(reply, body.error.message);
    return answer(reply, async () => {
      const { createdAt, wallet: _w, edKey: _k, ...p } = await serial(() => people.register(body.data.name));
      return { ...p, createdAt };
    });
  });
  app.get('/demo/participants', async () => people.list());
  // The phone sign-up link for the QR code on the laptop: the laptop's LAN addresses (phones cannot open localhost),
  // on the port of the LAN-reachable web server (LEGX_PHONE_PORT, default 5174).
  app.get('/demo/phone-urls', async () => {
    const port = Number(process.env.LEGX_PHONE_PORT ?? 5174);
    const ips = Object.values(networkInterfaces())
      .flat()
      .filter((i) => i && i.family === 'IPv4' && !i.internal)
      .map((i) => i?.address as string);
    return { urls: ips.map((ip) => `http://${ip}:${port}/register`) };
  });

  app.post('/demo/deals', { bodyLimit: PDF_MAX + 64 * 1024 }, async (req, reply) => {
    let form: FormData;
    try {
      form = await new Request('http://local/', {
        method: 'POST',
        headers: { 'content-type': String(req.headers['content-type']) },
        body: req.body as Buffer,
      }).formData();
    } catch {
      return bad(reply, 'the body is not multipart/form-data');
    }
    const pdf = form.get('contractPdf');
    form.delete('contractPdf');
    const fields = DealForm.safeParse(Object.fromEntries(form));
    if (!fields.success) return bad(reply, fields.error.message);
    if (!(pdf instanceof Blob) || pdf.type !== 'application/pdf' || pdf.size === 0 || pdf.size > PDF_MAX)
      return bad(reply, 'contractPdf: an application/pdf file of at most 5 MB');
    const bytes = Buffer.from(await pdf.arrayBuffer());
    if (bytes.subarray(0, 5).toString('latin1') !== '%PDF-') return bad(reply, 'contractPdf: not a PDF');
    const sender = people.get(fields.data.senderRid);
    const recipient = people.get(fields.data.recipientRid);
    if (!sender || !recipient || sender === recipient)
      return reply.code(422).send({ error: 'unknown_participant', message: 'two different registered participants' });
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    const base = `${req.protocol}://${req.host}`;
    return answer(reply, () =>
      serial(async () => {
        const d = await ProductDeal.create(app, deps, {
          sender,
          recipient,
          amountXrp: fields.data.amountXrp,
          terms: fields.data.terms,
          pdf: (id) => {
            mkdirSync(pdfDir, { recursive: true });
            writeFileSync(join(pdfDir, `${id}.pdf`), bytes);
            return { sha256, url: `${base}/demo/deals/${id}/contract.pdf` };
          },
        });
        deals.set(d.id, d);
        return d.summary();
      }),
    );
  });
  app.get<{ Querystring: { status?: string } }>('/demo/deals', async (req) =>
    [...deals.values()]
      .filter((d) => req.query.status === undefined || d.status === req.query.status)
      .map((d) => d.summary()),
  );
  app.get<{ Params: { id: string } }>('/demo/deals/:id', async (req, reply) => {
    const d = deals.get(req.params.id);
    return d ? d.summary() : reply.code(404).send({ error: 'unknown_deal', message: req.params.id });
  });
  app.get<{ Params: { id: string } }>('/demo/deals/:id/contract.pdf', async (req, reply) => {
    const d = deals.get(req.params.id);
    if (!d) return reply.code(404).send({ error: 'unknown_deal', message: req.params.id });
    return reply.type('application/pdf').send(readFileSync(join(pdfDir, `${d.id}.pdf`)));
  });
  app.post<{ Params: { id: string } }>('/demo/deals/:id/approve', async (req, reply) => {
    const d = deals.get(req.params.id);
    if (!d) return reply.code(404).send({ error: 'unknown_deal', message: req.params.id });
    const body = ApproveBody.safeParse(json(req.body));
    if (!body.success) return bad(reply, body.error.message);
    const who = people.get(body.data.rid);
    if (!who) return reply.code(403).send({ error: 'wrong_actor', message: 'unknown participant' });
    return answer(reply, () =>
      serial(async () => {
        await d.approve(who, body.data.stage);
        return d.summary();
      }),
    );
  });
}
