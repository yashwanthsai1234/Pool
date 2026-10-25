#!/bin/sh
# Final regression: every suite at once, one log per suite in build/regression/.
cd "$(dirname "$0")/.." && export PATH="$PWD/.tools/node/bin:$PATH"
OUT=build/regression; mkdir -p $OUT
docker rm -f legx-final-xrpld legx-final-pg >/dev/null 2>&1
docker run -d --name legx-final-xrpld --platform linux/amd64 -p 127.0.0.1:6200:6006 -v "$PWD/ci:/etc/xrpld:ro" rippleci/xrpld:3.4.1 --standalone >/dev/null
docker run -d --name legx-final-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:5600:5432 postgres:18.6-trixie >/dev/null
export XRPLD_WS=ws://127.0.0.1:6200 LEGX_PG_URL=postgres://postgres:pw@127.0.0.1:5600/postgres LEGX_PG_CONTAINER=legx-final-pg
run() { name=$1; shift; ( "$@" >"$OUT/$name.log" 2>&1; echo "$name exit=$?" >>"$OUT/summary.txt" ) & }
: >"$OUT/summary.txt"
run unit pnpm vitest run --project unit
run browser env LEGX_BROWSER=1 pnpm vitest run --project browser --project vault-browser --project core-browser
run typecheck pnpm typecheck
run lint pnpm exec biome check .
run webbuild pnpm --filter @legx/web test
sleep 15; run integration pnpm vitest run --project integration
wait
for f in tests/system/test/*.test.ts; do pnpm vitest run --project system "$f" >>"$OUT/system.log" 2>&1; echo "system $(basename $f) exit=$?" >>"$OUT/summary.txt"; done
docker rm -f legx-final-xrpld legx-final-pg >/dev/null 2>&1
echo DONE >>"$OUT/summary.txt"
