export type { DealWatch } from './locks.ts';
export { NOTIFY_CHANNEL, OBSERVATION_TOPIC, pgNotify, recordObservation, type Step } from './observe.ts';
export {
  ALERT_TOPIC,
  type EvidenceInput,
  LEDGER_TOPIC,
  WatcherService,
  type WatcherServiceOptions,
} from './service.ts';
