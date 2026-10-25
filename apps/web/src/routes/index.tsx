import { createFileRoute } from '@tanstack/react-router';
import { Icon, Page } from '../lib/demo-ui.tsx';
import { PhoneSignupQr } from '../lib/phone-qr.tsx';

const TILES = [
  {
    href: '/register',
    where: 'Phone',
    title: 'Register',
    text: 'Enter your name to get your own keys and ID.',
    step: 1,
  },
  { href: '/me', where: 'Phone', title: 'My deals', text: 'Do your step of each deal and watch it move.', step: 2 },
  {
    href: '/deals',
    where: 'Laptop',
    title: 'Deal page',
    text: 'Create a deal; see locked and released escrows.',
    step: 3,
  },
  { href: '/dashboard', where: 'Projector', title: 'Dashboard', text: 'Live ledger, gate checks and attack mode.' },
  { href: '/lawyers', where: 'Laptop', title: 'Lawyer console', text: 'The lawyers’ guided walkthrough.' },
] as const;

function Home() {
  return (
    <Page title="LegX escrow demo" subtitle="Two people, one deal, money held safely until both sides are done." wide>
      <PhoneSignupQr />
      <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {TILES.map((t) => (
          <li key={t.href}>
            <a
              href={t.href}
              className="group flex h-full min-h-32 flex-col gap-2 rounded-2xl border border-soft bg-surface p-5 hover:border-primary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-fg"
            >
              <span className="flex items-center justify-between gap-2 text-sm font-semibold text-muted">
                <span>{'step' in t ? `Step ${t.step} · ${t.where}` : t.where}</span>
                <span className="text-primary">{Icon.arrow()}</span>
              </span>
              <span className="text-[20px] font-bold text-fg">{t.title}</span>
              <span className="text-base text-muted">{t.text}</span>
            </a>
          </li>
        ))}
      </ul>
    </Page>
  );
}

export const Route = createFileRoute('/')({ component: Home });
