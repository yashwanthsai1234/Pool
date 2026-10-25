// @legx/server: the composed Fastify process (IMPLEMENTATION 3.7).
export {
  BODY_LIMIT,
  buildServer,
  DEFAULT_CSP,
  type HealthBody,
  LIVE_PATH,
  type Server,
} from './compose.ts';
export {
  assertProfile,
  DEMO_ENV_PREFIX,
  type PortSpec,
  type ProfileName,
  ProfileViolation,
  profileFromEnv,
  type ZkSettings,
} from './config.ts';
export type { ServerDeps } from './deps.ts';
export { type FeedRow, LiveHub, type LiveOptions, type LiveSource } from './live.ts';
export { NOTIFY_CHANNEL, type PgLiveSource, pgLiveSource } from './pgSource.ts';
