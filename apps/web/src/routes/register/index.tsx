// /register (phone): one name, one button, then straight to My deals (build/UX.md principle 6).
import { useMutation } from '@tanstack/react-query';
import { createFileRoute, useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { registerParticipant, savedRid, saveRid, useParticipants } from '../../lib/demo-deals.tsx';
import { Card, Field, INPUT, Page, PrimaryAction, RidChip, Toast, WELCOME_KEY } from '../../lib/demo-ui.tsx';

function Register() {
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const known = savedRid();
  const people = useParticipants();
  const current = known ? people.data?.find((p) => p.rid === known) : undefined;
  const reg = useMutation({
    mutationFn: registerParticipant,
    onSuccess: (p) => {
      saveRid(p.rid);
      try {
        sessionStorage.setItem(WELCOME_KEY, JSON.stringify({ name: p.name, rid: p.rid }));
      } catch {
        // private window: no greeting, the redirect still happens
      }
      void navigate({ to: '/me' });
    },
  });
  const trimmed = name.trim();
  return (
    <Page
      title="Register"
      subtitle="Your name, and this phone gets its own keys and ID."
      action={
        <PrimaryAction
          type="submit"
          form="register-form"
          pending={reg.isPending}
          disabledReason={trimmed || reg.isPending ? undefined : 'Type your name first'}
        >
          {reg.isPending ? 'Registering…' : 'Register'}
        </PrimaryAction>
      }
    >
      {current ? (
        <Card label="Already registered">
          <p className="text-base text-muted">This phone is already registered as</p>
          <RidChip name={current.name} rid={current.rid} fingerprint={current.fingerprint} />
          <a className="inline-flex min-h-12 items-center font-semibold text-primary underline" href="/me">
            Go to my deals
          </a>
        </Card>
      ) : null}
      <form
        id="register-form"
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (trimmed) reg.mutate(trimmed);
        }}
      >
        <Field label="Your name">
          <input
            className={INPUT}
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoComplete="name"
            placeholder="Alice"
          />
        </Field>
      </form>
      {reg.error ? (
        <Toast
          toast={{
            tone: 'error',
            message: `Could not register. Check the connection and try again. (server: ${reg.error.message.slice(0, 120)})`,
          }}
        />
      ) : null}
    </Page>
  );
}

export const Route = createFileRoute('/register/')({ component: Register });
