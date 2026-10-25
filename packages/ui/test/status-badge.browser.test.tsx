import { describe, expect, it } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { type Status, StatusBadge } from '../src/index.ts';

describe('StatusBadge: never colour alone', () => {
  for (const [status, label] of [
    ['pass', 'PASS'],
    ['fail', 'FAIL'],
    ['pending', 'PENDING'],
  ] as [Status, string][]) {
    it(`${status} has a text label and an icon`, async () => {
      const screen = await render(<StatusBadge status={status} />);
      await expect.element(page.getByText(label)).toBeVisible();
      expect(screen.container.querySelector('svg[aria-hidden="true"]')).not.toBeNull();
    });
  }
});
