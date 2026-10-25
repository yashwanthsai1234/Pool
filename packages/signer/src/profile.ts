// A demo implementation running in production is a silent security hole (IMPLEMENTATION 3.6 "Think hard"):
// every demo-only signer calls this first and refuses to exist outside the demo profile.
import { Profile } from '@legx/contracts/values';

/** Throws unless `LEGX_PROFILE` is exactly `demo`. An unset or unknown profile is treated as production. */
export function assertDemoProfile(what: string, env: Readonly<Record<string, string | undefined>> = process.env): void {
  const parsed = Profile.safeParse(env.LEGX_PROFILE);
  if (!parsed.success || parsed.data !== 'demo') {
    throw new Error(`${what} is demo-only and refuses to start unless LEGX_PROFILE=demo`);
  }
}
