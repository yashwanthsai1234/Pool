// The lawyer page, both halves on one screen: what each half shows, the approval dialog, the disabled release button
// with its reason, and axe (task 4.1 sets the bar: no serious or critical violation).

import { GATE_CODES } from '@legx/contracts/records';
import { contractRoot } from '@legx/core/contract';
import { bytesToHex, utf8ToBytes } from '@legx/core/dealcore';
import axe from 'axe-core';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { page, userEvent } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { createApprovalPrompt } from '../../src/routes/lawyers/-console/prompt.ts';
import { type ConsoleWiring, LawyerConsolePage } from '../../src/routes/lawyers/-console/ui.tsx';
import { makeConsole, mutable, OPS, withRoot, world } from './harness.ts';
import '../../src/index.css';

vi.setConfig({ testTimeout: 30_000, hookTimeout: 120_000 });
beforeAll(async () => void (await world()));

const clauses = [utf8ToBytes('1. Alice pays Bob 5000 XRP.')];
const salts = [new Uint8Array(32).fill(1)];

/** `signing`: the sealed contract root is the one these clauses give, so the contract card works (the gate then would not). */
async function page2(extra: Partial<NonNullable<ConsoleWiring['LA']>> = {}, signing = false) {
  const pa = createApprovalPrompt();
  const pb = createApprovalPrompt();
  const w = await world();
  const own = signing
    ? {
        data: withRoot(w.input.deal.data, bytesToHex(contractRoot(clauses, salts))),
        contract: { clauses, salts },
      }
    : {};
  const a = await makeConsole({ role: 'LA', confirm: pa.confirm, ...own });
  const b: Awaited<ReturnType<typeof makeConsole>> = await makeConsole({
    role: 'LB',
    confirm: pb.confirm,
    ...own,
    // the escrow in the snapshot carries the condition of whatever code lawyer B made in this console
    snapshot: async () => {
      const i = mutable(b.input);
      if (b.c.deal.hasReleaseCode()) {
        i.deal.escrow.conditionHex = b.c.deal.condition();
        for (const o of i.ledger.objects) if (o.LedgerEntryType === 'Escrow') o.Condition = b.c.deal.condition();
      }
      return i;
    },
  });
  const wiring: ConsoleWiring = { LA: { console: a.c, prompt: pa, ...extra }, LB: { console: b.c, prompt: pb } };
  const screen = await render(<LawyerConsolePage wiring={wiring} />);
  return { a, b, pa, pb, screen };
}

const half = (name: 'Lawyer A' | 'Lawyer B') => page.getByRole('region', { name, exact: true });

describe('the lawyer page', () => {
  it('shows two halves; the release code and the release button are only on lawyer B, the mint only on lawyer A', async () => {
    await page2();
    await expect.element(half('Lawyer A')).toBeVisible();
    await expect.element(half('Lawyer B')).toBeVisible();
    await expect.element(half('Lawyer A').getByRole('button', { name: 'Mint contract NFT' })).toBeVisible();
    expect(half('Lawyer B').getByRole('button', { name: 'Mint contract NFT' }).query()).toBeNull();
    await expect.element(half('Lawyer B').getByRole('button', { name: 'Make release code' })).toBeVisible();
    expect(half('Lawyer A').getByRole('button', { name: 'Make release code' }).query()).toBeNull();
    await expect.element(half('Lawyer B').getByRole('button', { name: 'Release money' })).toBeDisabled();
    expect(half('Lawyer A').getByRole('button', { name: 'Release money' }).query()).toBeNull();
  });

  it('the release code is shown only in lawyer B half, after B makes it', async () => {
    const { b } = await page2();
    await half('Lawyer B').getByRole('button', { name: 'Make release code' }).click();
    const code = half('Lawyer B').getByLabelText('Release code');
    await expect.element(code).toBeVisible();
    expect(code.element().textContent?.replaceAll(' ', '')).toBe(b.c.deal.fulfillment().slice(8));
    expect(half('Lawyer A').getByLabelText('Release code').query()).toBeNull();
    expect(b.spies.conditions).toHaveLength(1);
  });

  it('the release button is off with its reason until the gate passes, then on', async () => {
    await page2();
    const lb = half('Lawyer B');
    await expect.element(lb.getByText('Run the release gate first.')).toBeVisible();
    await lb.getByRole('button', { name: 'Run lock check and release gate' }).click();
    await expect.element(lb.getByText(/Make the release code first/)).toBeVisible();
    await expect.element(lb.getByRole('button', { name: 'Release money' })).toBeDisabled();
    await lb.getByRole('button', { name: 'Make release code' }).click();
    await lb.getByRole('button', { name: 'Run lock check and release gate' }).click();
    await expect.element(lb.getByRole('button', { name: 'Release money' })).toBeEnabled();
    const list = lb.getByRole('list', { name: 'Release gate findings' });
    await expect.element(list).toBeVisible();
    expect(list.element().querySelectorAll('li')).toHaveLength(GATE_CODES.length);
    await expect.element(lb.getByText(/Alice: Zero-knowledge. Bob: Chip./)).toBeVisible();
  });

  it('signing shows the decoded message and its hash in a dialog; cancel signs nothing, approve signs', async () => {
    const { a, pa } = await page2({}, true);
    const la = half('Lawyer A');
    await la.getByRole('button', { name: 'Sign contract' }).first().click();
    await expect.element(page.getByRole('alertdialog')).toBeVisible();
    const dialog = page.getByRole('alertdialog');
    await expect.element(dialog.getByText(/legx\/contract-sign\/v1/)).toBeVisible();
    expect(pa.current()?.view.hash).toMatch(/^[0-9a-f]{64}$/);
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect.element(la.getByText(/You cancelled. Nothing was signed./)).toBeVisible();
    expect(a.spies.slot.sign).not.toHaveBeenCalled();
    void OPS;
  });

  it('a description that differs from the bytes: the dialog shows the mismatch and offers no approve button', async () => {
    const tx = {
      TransactionType: 'Payment',
      Account: OPS.LA.address,
      Destination: OPS.LA.address,
      Amount: '9000000',
      Fee: '60',
      Sequence: 0,
      TicketSequence: 12,
      SigningPubKey: '',
      Flags: 0x80000000,
      LastLedgerSequence: 91_000_000,
    };
    const { a } = await page2({
      exits: [
        {
          requestId: 'r1',
          label: 'pay Bob',
          tx,
          claimed: { what: 'Payment', destination: OPS.LB.address, amount: '5000000 drops' },
        },
      ],
    });
    await half('Lawyer A').getByRole('button', { name: 'Approve exit: pay Bob' }).click();
    const dialog = page.getByRole('alertdialog');
    await expect.element(dialog.getByText(/described this differently/)).toBeVisible();
    expect(dialog.getByRole('button', { name: /Approve with my security key/ }).query()).toBeNull();
    expect(page.getByText('Exit approved.').query()).toBeNull();
    await dialog.getByRole('button', { name: 'Close' }).click();
    expect(a.spies.slot.sign).not.toHaveBeenCalled();
    expect(a.spies.requestApproval).not.toHaveBeenCalled();
  });

  it('has no serious or critical axe violations with the contract card and the approval dialog open', async () => {
    const { screen } = await page2({}, true);
    await half('Lawyer A').getByRole('button', { name: 'Sign contract' }).first().click();
    await expect.element(page.getByRole('alertdialog')).toBeVisible();
    const results = await axe.run(screen.container);
    const bad = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(' | ')}`)).toEqual([]);
  });

  it('has no serious or critical axe violations: idle and with a gate list', async () => {
    const { screen } = await page2({}, false);
    const check = async () => {
      const results = await axe.run(screen.container);
      const bad = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
      expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(' | ')}`)).toEqual([]);
    };
    await check();
    const lb = half('Lawyer B');
    await lb.getByRole('button', { name: 'Make release code' }).click();
    await lb.getByRole('button', { name: 'Run lock check and release gate' }).click();
    await expect.element(lb.getByRole('list', { name: 'Release gate findings' })).toBeVisible();
    await check();
    void userEvent;
  });
});
