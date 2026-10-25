import fc from 'fast-check';
import { afterEach, describe, expect, it } from 'vitest';
import { assertHostAllowed, assertNotMainnet, connect, devnetEnv, standaloneEnv, testnetEnv } from '../src/index.ts';

const GENESIS = { ledger: { parent_hash: '0'.repeat(64), close_time: 0, total_coins: '100000000000000000' } };
const fake = (networkId: number | undefined, ledger: unknown, extra: object = { peers: 0, validation_quorum: 0 }) => ({
  request: async (r: { command: string }) => {
    if (r.command === 'server_info')
      return { result: { info: { ...extra, ...(networkId === undefined ? {} : { network_id: networkId }) } } };
    if (ledger === undefined) throw new Error('lgrNotFound');
    return { result: ledger };
  },
});

describe('P2.1-08 Mainnet guard', () => {
  const saved = process.env.NETWORK;
  afterEach(() => {
    if (saved === undefined) delete process.env.NETWORK;
    else process.env.NETWORK = saved;
  });

  it('NETWORK=mainnet throws before any connection, for every environment', async () => {
    process.env.NETWORK = 'MainNet';
    for (const env of [standaloneEnv(), testnetEnv(), devnetEnv()]) {
      await expect(connect(env)).rejects.toThrow(/NETWORK=mainnet/);
    }
  });

  it.each([
    'wss://xrplcluster.com',
    'wss://s1.ripple.com',
    'wss://s2.ripple.com:51233',
    'wss://xrpl.ws',
    'wss://XRPLCLUSTER.com/',
  ])('known Mainnet URL %s is refused without any request', async (url) => {
    await expect(connect({ name: 'testnet', wsUrl: url })).rejects.toThrow(/Refusing/);
    await expect(connect({ name: 'standalone', wsUrl: url })).rejects.toThrow(/Refusing/);
  });

  it('rejects unknown environment names and non-websocket URLs', () => {
    expect(() => assertHostAllowed('mainnet' as never, 'ws://127.0.0.1:1')).toThrow(/unknown environment/);
    expect(() => assertHostAllowed('standalone', 'http://127.0.0.1:1')).toThrow(/invalid/);
    expect(() => assertHostAllowed('standalone', 'not a url')).toThrow(/invalid/);
  });

  it('allows the local and test hosts', () => {
    assertHostAllowed('standalone', 'ws://127.0.0.1:6101');
    assertHostAllowed('standalone', 'ws://localhost:6006');
    assertHostAllowed('testnet', testnetEnv().wsUrl);
    assertHostAllowed('devnet', devnetEnv().wsUrl);
  });

  it('standalone refuses any public host, test networks refuse any non rippletest.net host (property)', () => {
    fc.assert(
      fc.property(fc.domain(), (d) => {
        fc.pre(!d.endsWith('rippletest.net'));
        expect(() => assertHostAllowed('standalone', `ws://${d}`)).toThrow(/Refusing/);
        expect(() => assertHostAllowed('testnet', `wss://${d}`)).toThrow(/Refusing/);
      }),
    );
  });

  it('look-alike hosts do not slip through', () => {
    expect(() => assertHostAllowed('testnet', 'wss://rippletest.net.evil.com')).toThrow(/Refusing/);
    expect(() => assertHostAllowed('testnet', 'wss://xrplcluster.com.rippletest.net.evil.io')).toThrow(/Refusing/);
    expect(() => assertHostAllowed('standalone', 'ws://127.0.0.1.evil.com')).toThrow(/Refusing/);
    expect(() => assertHostAllowed('standalone', 'ws://s1.ripple.com')).toThrow(/Mainnet/);
  });

  it('server_info network_id must match the environment (Mainnet is 0 or missing)', async () => {
    await expect(assertNotMainnet('testnet', fake(0, undefined))).rejects.toThrow(/network_id 0/);
    await expect(assertNotMainnet('testnet', fake(undefined, undefined))).rejects.toThrow(/network_id 0/);
    await expect(assertNotMainnet('devnet', fake(1, undefined))).rejects.toThrow(/network_id 1/);
    await expect(assertNotMainnet('standalone', fake(1, GENESIS))).rejects.toThrow(/network_id 1/);
    await expect(assertNotMainnet('testnet', fake(1, undefined))).resolves.toBeUndefined();
    await expect(assertNotMainnet('devnet', fake(2, undefined))).resolves.toBeUndefined();
  });

  it('standalone must prove a genesis ledger 1 when it still has it', async () => {
    await expect(assertNotMainnet('standalone', fake(0, GENESIS))).resolves.toBeUndefined();
    await expect(
      assertNotMainnet('standalone', fake(0, { ledger: { ...GENESIS.ledger, parent_hash: 'AB'.repeat(32) } })),
    ).rejects.toThrow(/not a genesis/);
    await expect(
      assertNotMainnet('standalone', fake(0, { ledger: { ...GENESIS.ledger, total_coins: '99999999999000000' } })),
    ).rejects.toThrow(/not a genesis/);
    await expect(
      assertNotMainnet('standalone', fake(0, GENESIS, { peers: 20, validation_quorum: 28 })),
    ).resolves.toBeUndefined();
  });

  it('without ledger 1 (online_delete) a standalone needs zero peers and quorum 0; a Mainnet-like node is refused', async () => {
    await expect(assertNotMainnet('standalone', fake(0, undefined))).resolves.toBeUndefined();
    await expect(
      assertNotMainnet('standalone', fake(0, undefined, { peers: 21, validation_quorum: 28 })),
    ).rejects.toThrow(/may be Mainnet/);
    await expect(
      assertNotMainnet('standalone', fake(0, undefined, { peers: 0, validation_quorum: 28 })),
    ).rejects.toThrow(/may be Mainnet/);
    await expect(assertNotMainnet('standalone', fake(0, undefined, {}))).rejects.toThrow(/may be Mainnet/);
  });
});
