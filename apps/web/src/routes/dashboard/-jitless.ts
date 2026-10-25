// zod 4 probes `new Function('')` the first time a schema is built. Under our Trusted Types CSP the caught probe is still
// reported as a violation, so the dashboard turns the probe off before any schema exists. This file must be the FIRST import
// of every dashboard module that builds a zod schema (ES modules run in import order).
// Source: node_modules/zod/v4/core/util.js (allowsEval skips the probe under `jitless`); https://zod.dev/api (z.config)
import { z } from 'zod';

z.config({ jitless: true });
