// A relay that lies to one reader: it rewrites, drops, repeats or reorders what `receive` returns.
import type { FrostRelayPort, RelayedMessage } from '@legx/contracts/ports';

export class TamperRelay implements FrostRelayPort {
  readonly #inner: FrostRelayPort;
  readonly #rewrite: (recipient: string, r: RelayedMessage) => RelayedMessage | RelayedMessage[] | null;
  constructor(
    inner: FrostRelayPort,
    rewrite: (recipient: string, r: RelayedMessage) => RelayedMessage | RelayedMessage[] | null,
  ) {
    this.#inner = inner;
    this.#rewrite = rewrite;
  }
  send(message: Parameters<FrostRelayPort['send']>[0]) {
    return this.#inner.send(message);
  }
  async receive(sessionId: never, recipient: never, afterSeq: number) {
    const got = await this.#inner.receive(sessionId, recipient, afterSeq);
    return got.flatMap((r) => {
      const out = this.#rewrite(recipient, r);
      return out === null ? [] : Array.isArray(out) ? out : [out];
    });
  }
}
