// The fixed schema of the window-level messages between the app page and the vault frame (DESIGN 6.4 "Code
// integrity"). Both ends check every message against it and drop what does not fit: the frame checks `init`, the app
// checks `ready` and `refused`. Everything after the handshake travels on the MessagePort in @legx/vault's own schema.
// Source: https://html.spec.whatwg.org/multipage/web-messaging.html#posting-messages (origin and source of a message)
// Source: https://zod.dev/api (strict objects reject unknown keys)
import { z } from 'zod';

const hex64 = z.string().regex(/^[0-9a-f]{64}$/);

/** App to frame: which role this vault serves. The port that carries the vault RPC travels in the transfer list. */
export const InitMessage = z.strictObject({
  legxVaultHost: z.literal(1),
  type: z.literal('init'),
  role: z.enum(['alice', 'bob', 'lawyerA', 'lawyerB']),
});

/** Frame to app: the code matched the signed release (`ready`) or did not (`refused`). */
export const FrameMessage = z.discriminatedUnion('type', [
  z.strictObject({
    legxVaultHost: z.literal(1),
    type: z.literal('ready'),
    version: z.string().max(32),
    manifestHash: hex64,
  }),
  z.strictObject({ legxVaultHost: z.literal(1), type: z.literal('refused'), code: z.literal('CODE_HASH_MISMATCH') }),
]);

export type InitMessage = z.infer<typeof InitMessage>;
export type FrameMessage = z.infer<typeof FrameMessage>;
