// The rotation screen after "my share was stolen" (P4.7-20): a new DKG, a 4-of-4 SignerListSet signed by all four
// slots, a new seal, and for a lawyer slot new contract signatures and an NFT. Each step shows its own check; the old
// key is shown as retired only after the ledger validated the new signer list.
import type { SlotName } from '@legx/core/frost';
import type { RotationStep } from '@legx/core/frostRules';
import { Button, StatusBadge } from '@legx/ui';
import type { StepRun, StepState } from '@legx/vault/frost/rotation';
import { useState } from 'react';

export type RotationScreenProps = { slot: SlotName; steps: Partial<Record<RotationStep, StepRun>> };

const BADGE = { waiting: 'pending', running: 'pending', done: 'pass', failed: 'fail' } as const;

export function RotationScreen(p: RotationScreenProps) {
  const [states, setStates] = useState<StepState[]>([]);
  const [retired, setRetired] = useState(false);
  const [running, setRunning] = useState(false);
  const start = async () => {
    setRunning(true);
    const { runRotation } = await import('@legx/vault/frost/rotation'); // loads the core rules only when used
    await runRotation({
      ...p,
      onUpdate: (s, r) => {
        setStates(s);
        setRetired(r);
      },
    });
    setRunning(false);
  };
  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="rot-title">
      <h1 id="rot-title" className="text-2xl font-bold">
        Replace the key of slot {p.slot}
      </h1>
      <p>A stolen share cannot be fixed with a refresh. The slot gets a new key, and the ledger must accept it.</p>
      <Button onClick={start} disabled={running || states.length > 0}>
        Start the rotation
      </Button>
      <ol aria-label="Rotation steps" className="flex flex-col gap-1">
        {states.map((s) => (
          <li key={s.step}>
            <StatusBadge status={BADGE[s.status]} /> {s.title}
            {s.check ? <span className="block text-muted">{s.check}</span> : null}
          </li>
        ))}
      </ol>
      <p role="status">{retired ? 'The old slot key is retired.' : 'The old slot key is still active.'}</p>
    </section>
  );
}
