// Regenerates collector/otel-collector.yaml from the allow-list. Run: node packages/observability/scripts/write-collector-config.ts
import { writeFileSync } from 'node:fs';
import { collectorConfig } from '../src/collector.ts';

writeFileSync(new URL('../collector/otel-collector.yaml', import.meta.url), collectorConfig());
