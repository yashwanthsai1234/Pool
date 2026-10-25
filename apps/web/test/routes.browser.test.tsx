import { QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import axe from 'axe-core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { createQueryClient } from '../src/lib/query.ts';
import { createAppRouter } from '../src/router.tsx';
import '../src/index.css';

const ROUTES = [
  { path: '/party/alice', heading: 'Hello Alice, no deal yet' },
  { path: '/party/bob', heading: 'Hello Bob, no deal yet' },
  { path: '/party/mallory', heading: 'Unknown role' },
  { path: '/lawyers', heading: 'No deals assigned' },
  { path: '/dashboard', heading: 'Waiting for the first deal' },
];

let consoleError: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  consoleError = vi.spyOn(console, 'error');
});
afterEach(() => consoleError.mockRestore());

async function renderRoute(path: string) {
  const queryClient = createQueryClient();
  const router = createAppRouter(queryClient, path);
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('routes: empty states and accessibility', () => {
  for (const { path, heading } of ROUTES) {
    // P4.1-01
    it(`${path} renders its empty state with no console error`, async () => {
      await renderRoute(path);
      await expect.element(page.getByRole('heading', { name: heading })).toBeVisible();
      expect(consoleError).not.toHaveBeenCalled();
    });

    // P4.1-07
    it(`${path} has no serious or critical axe violations`, async () => {
      const screen = await renderRoute(path);
      await expect.element(page.getByRole('heading', { name: heading })).toBeVisible();
      const results = await axe.run(screen.container);
      const bad = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
      expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(' | ')}`)).toEqual([]);
    });
  }

  it('the dashboard uses the projector theme and the phone routes do not', async () => {
    const dash = await renderRoute('/dashboard');
    await expect.element(page.getByRole('main')).toHaveAttribute('data-theme', 'projector');
    await dash.unmount();
    await renderRoute('/lawyers');
    await expect.element(page.getByRole('main')).not.toHaveAttribute('data-theme');
  });
});
