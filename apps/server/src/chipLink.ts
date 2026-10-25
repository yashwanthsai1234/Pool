// The relay for the phone's sealed chip bundle (task 4.6). The server holds ciphertext only: the key that opens it
// exists only in the console that showed the QR code, so nothing here ever decrypts. A session is opened by the
// console (PUT), takes ONE post from the phone (a replay is refused), and the console polls it (GET), which deletes it.
// The routes are unauthenticated by design (a phone has no signing key); the QR's one-time key is the secret, and the
// store is bounded in size, count and time.
// Source: https://fastify.dev/docs/latest/Reference/Routes/  Source: https://www.rfc-editor.org/rfc/rfc9180

import type { FastifyInstance } from 'fastify';

export const CHIP_LINK_PREFIX = '/chip-link/';
const HEX32 = /^[0-9a-f]{32}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
/** X-Wing encapsulation is 1120 bytes; the transfer is at most a few hundred KB (1 MiB per field is a wire cap). */
const MAX_FIELD = 4 * 1024 * 1024;

export interface ChipLinkOptions {
  /** Milliseconds a session and its bundle live. */
  readonly ttlMs?: number;
  readonly maxSessions?: number;
  readonly now?: () => number;
}

interface Slot {
  readonly expires: number;
  bundle?: { sessionId: string; enc: string; ct: string };
}

export function registerChipLink(app: FastifyInstance, o: ChipLinkOptions = {}): void {
  const ttl = o.ttlMs ?? 5 * 60_000;
  const max = o.maxSessions ?? 256;
  const now = o.now ?? Date.now;
  const slots = new Map<string, Slot>();
  const live = (id: string): Slot | undefined => {
    for (const [k, s] of slots) if (s.expires <= now()) slots.delete(k);
    return slots.get(id);
  };
  const idOf = (p: unknown): string | undefined => {
    const id = (p as { sessionId?: string }).sessionId;
    return id !== undefined && HEX32.test(id) ? id : undefined;
  };

  app.put(`${CHIP_LINK_PREFIX}:sessionId`, async (req, reply) => {
    const id = idOf(req.params);
    if (!id) return reply.code(400).send({ error: 'bad_session' });
    if (live(id)) return reply.code(409).send({ error: 'session_exists' });
    if (slots.size >= max) return reply.code(429).send({ error: 'too_many_sessions' });
    slots.set(id, { expires: now() + ttl });
    return reply.code(204).send();
  });

  app.post(`${CHIP_LINK_PREFIX}:sessionId`, async (req, reply) => {
    const id = idOf(req.params);
    if (!id) return reply.code(400).send({ error: 'bad_session' });
    let b: { sessionId?: unknown; enc?: unknown; ct?: unknown };
    try {
      b = JSON.parse(Buffer.isBuffer(req.body) ? req.body.toString('utf8') : String(req.body));
    } catch {
      return reply.code(400).send({ error: 'bad_body' });
    }
    const field = (x: unknown): x is string =>
      typeof x === 'string' && x.length > 0 && x.length <= MAX_FIELD && B64URL.test(x);
    if (b.sessionId !== id || !field(b.enc) || !field(b.ct)) return reply.code(400).send({ error: 'bad_body' });
    const s = live(id);
    if (!s) return reply.code(404).send({ error: 'unknown_session' });
    if (s.bundle) return reply.code(409).send({ error: 'already_posted' });
    s.bundle = { sessionId: id, enc: b.enc, ct: b.ct };
    return reply.code(204).send();
  });

  app.get(`${CHIP_LINK_PREFIX}:sessionId`, async (req, reply) => {
    const id = idOf(req.params);
    const s = id ? live(id) : undefined;
    if (!id || !s) return reply.code(404).send({ error: 'unknown_session' });
    if (!s.bundle) return reply.code(204).send(); // not yet: poll again
    slots.delete(id);
    return reply.code(200).send(s.bundle);
  });
}
