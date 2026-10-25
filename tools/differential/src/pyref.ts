// The Python side of the A/B tests: tools/py-ref/cross.py driven over a pipe, one JSON line each way.
import { type ChildProcessWithoutNullStreams, spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

const PY_DIR = new URL('../../py-ref/', import.meta.url).pathname;

export class PyRef {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #lines: AsyncIterator<string>;
  #stderr = '';

  constructor() {
    this.#child = spawn('uv', ['run', '--quiet', '--project', PY_DIR, 'python', `${PY_DIR}cross.py`], {
      cwd: PY_DIR,
      env: { ...process.env, VIRTUAL_ENV: '' },
    });
    this.#child.stderr.on('data', (d: Buffer) => {
      this.#stderr += d.toString();
    });
    this.#lines = createInterface({ input: this.#child.stdout })[Symbol.asyncIterator]();
  }

  /** Sends `cases` in chunks (one pipe line each) and returns one result per case, in order. */
  async call<T>(op: 'ref' | 'xrpl', cases: readonly unknown[], chunk = 500): Promise<T[]> {
    const out: T[] = [];
    for (let i = 0; i < cases.length; i += chunk) {
      this.#child.stdin.write(`${JSON.stringify({ op, cases: cases.slice(i, i + chunk) })}\n`);
      const line = await this.#lines.next();
      if (line.done) throw new Error(`py-ref exited: ${this.#stderr}`);
      out.push(...(JSON.parse(line.value) as { results: T[] }).results);
    }
    return out;
  }

  close(): void {
    this.#child.stdin.end();
  }
}
