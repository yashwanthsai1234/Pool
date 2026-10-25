import { coreTargets } from '../targets/core.ts';
import { schemaTargets } from '../targets/schemas.ts';
import { zkTargets } from '../targets/zk.ts';
import type { Target } from './harness.ts';

export const targets: readonly Target[] = [...coreTargets, ...schemaTargets, ...zkTargets];
