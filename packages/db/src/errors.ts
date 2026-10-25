/** Another writer already holds this (deal_id, seq). The caller re-reads the head and retries (DESIGN 8.1). */
export class SeqTaken extends Error {
  readonly dealId: string;
  readonly seq: number;
  constructor(dealId: string, seq: number) {
    super(`seq ${seq} of deal ${dealId} is taken`);
    this.name = 'SeqTaken';
    this.dealId = dealId;
    this.seq = seq;
  }
}

/** The enrollment key has no evidence event that records its hash, so it must not be used (DESIGN 6.3, T-U-29). */
export class KeyNotRecorded extends Error {
  constructor(keyId: string) {
    super(`enrollment key ${keyId} has no evidence entry`);
    this.name = 'KeyNotRecorded';
  }
}
