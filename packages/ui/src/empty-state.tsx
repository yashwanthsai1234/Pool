import type { ReactNode } from 'react';

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <section className="mx-auto flex max-w-md flex-col items-center gap-3 p-8 text-center">
      <h2 className="text-2xl font-bold text-fg">{title}</h2>
      {children ? <p className="text-base text-muted">{children}</p> : null}
    </section>
  );
}
