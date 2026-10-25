// Screen text of the post-quantum binding, with no imports: the party route chunk loads it without the crypto (phone budget).
export const PQ_BINDING_TEXT = {
  waiting: 'Waiting for a second holder',
  keyMismatch: 'Key mismatch',
  sealMismatch: 'These values do not match the sealed deal. Nothing was signed.',
  progress: {
    signing: 'Signing with your post-quantum key',
    'cross-signing': 'Signing with the slot key',
    verifying: 'Checking the binding',
    submitting: 'Sending the binding',
  },
  help:
    'The post-quantum keys use the noble post-quantum library. It is not independently audited and does not claim ' +
    'constant-time execution. The binding proves consent if Ed25519 is broken later; it does not protect the money ' +
    'on the ledger.',
} as const;
