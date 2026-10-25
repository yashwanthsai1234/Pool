// I-S-A2: the web app (phone and lawyer console) has no `frame-ancestors`: any site can frame the approval and release
// screens (clickjacking). A <meta> CSP cannot carry the directive, so it must be a header (confirms I-5).
// I-S-A3: the production profile's Sepolia guard matches the word "sepolia" in the RPC URL only; an RPC URL named by
// chain id passes `assertProfile` (defence in depth: the trust record check still refuses chain 11155111).
import { describe, expect, it } from 'vitest';
import { assertProfile } from '../../../apps/server/src/config.ts';
import { CSP } from '../../../apps/web/csp.ts';

describe('I-S-A2 the web app may be framed', () => {
  // Source: https://www.w3.org/TR/CSP3/#directive-frame-ancestors (not supported in a <meta> element)
  // Source: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
  it("the web app's CSP names frame-ancestors", () => {
    expect(CSP).toMatch(/frame-ancestors 'none'/);
  });
});

describe('I-S-A3 production refuses a Sepolia RPC however it is named', () => {
  // Source: https://chainlist.org/chain/11155111 (Sepolia, chain id 11155111; many RPC hosts name only the id)
  it('an RPC URL that names the Sepolia chain id is refused', () => {
    expect(() =>
      assertProfile({
        profile: 'production',
        ports: {},
        zk: { devMode: false, rpcUrls: ['https://11155111.rpc.thirdweb.com'] },
      }),
    ).toThrow(/ZK_SEPOLIA/);
  });
});
