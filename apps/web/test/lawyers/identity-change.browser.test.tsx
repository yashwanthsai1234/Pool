// P4.8-21: a change of identity method mid-deal (a renewed passport, a formula change, or a fall back to the chip) needs a
// 4-of-4 seal update. The console says so, shows the old and new seal, shows who signed, and a refusal is a stall (O9) that
// is recorded once.
import type { PublicDealData } from '@legx/contracts/deal';
import { bytesToHex, dealSeal } from '@legx/core/dealcore';
import { describe, expect, it, vi } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { examplesOf } from '../../src/mocks/examples.ts';
import { IdentityChangePanel } from '../../src/routes/lawyers/-console/identity-change.tsx';
import '../../src/index.css';

const deal = { ...(examplesOf('PublicDealData')[0] as PublicDealData), identityPolicy: 'zk-or-chip' as const };
const next = { method: 'nfc-chip' as const, commitment: 'ab'.repeat(32) };
const show = async (over: Partial<Parameters<typeof IdentityChangePanel>[0]> = {}) => {
  const record = vi.fn(async () => {});
  const screen = await render(
    <IdentityChangePanel deal={deal} side="A" next={next} responses={{}} record={record} {...over} />,
  );
  return { screen, record };
};

describe('P4.8-21 identity method change', () => {
  it('says a 4-of-4 seal update is needed, shows the old and the new seal and every signer waiting', async () => {
    await show();
    await expect.element(page.getByText(/4-of-4 seal update/)).toBeVisible();
    await expect.element(page.getByTestId('old-seal')).toHaveTextContent(bytesToHex(dealSeal(deal)));
    await expect.element(page.getByTestId('new-seal')).not.toHaveTextContent(bytesToHex(dealSeal(deal)));
    for (const slot of ['A', 'LA', 'B', 'LB']) await expect.element(page.getByTestId(`signer-${slot}`)).toBeVisible();
    await expect.element(page.getByRole('status')).toMatchTextContent(/waiting/i);
  });

  it('a refusal shows as a stall (O9) and is recorded exactly once', async () => {
    const { screen, record } = await show({ responses: { A: 'signed', LA: 'signed', B: 'refused', LB: 'signed' } });
    await expect.element(page.getByRole('alert')).toMatchTextContent(/stall/i);
    await expect.element(page.getByTestId('signer-B')).toMatchTextContent(/refused/i);
    await vi.waitFor(() => expect(record).toHaveBeenCalledTimes(1));
    expect(record).toHaveBeenCalledWith({ state: 'refused', refusedBy: ['B'], reason: 'O9' });
    await screen.rerender(
      <IdentityChangePanel
        deal={deal}
        side="A"
        next={next}
        responses={{ A: 'signed', LA: 'signed', B: 'refused', LB: 'signed' }}
        record={record}
      />,
    );
    expect(record).toHaveBeenCalledTimes(1);
  });

  it('all four signed: the update is applied', async () => {
    const { record } = await show({ responses: { A: 'signed', LA: 'signed', B: 'signed', LB: 'signed' } });
    await expect.element(page.getByRole('status')).toMatchTextContent(/applied/i);
    expect(record).not.toHaveBeenCalled();
  });

  it('a method the sealed policy does not allow cannot be planned: no seal is shown', async () => {
    await show({ deal: { ...deal, identityPolicy: 'zk' } });
    await expect.element(page.getByRole('alert')).toMatchTextContent(/not allowed/i);
    expect(page.getByTestId('new-seal').elements()).toHaveLength(0);
  });
});
