// Converts RFC 5869 Appendix A (plain text) into hkdf/rfc5869-appendix-a.json.
// Usage: node packages/core/scripts/rfc5869-to-json.ts <rfc5869.txt> <out.json>
// Source: https://www.rfc-editor.org/rfc/rfc5869#appendix-A
import { readFileSync, writeFileSync } from 'node:fs';

const [input, output] = process.argv.slice(2);
if (!input || !output) throw new Error('usage: rfc5869-to-json.ts <rfc5869.txt> <out.json>');
const text = readFileSync(input, 'utf8');
const appendix = text
  .slice(text.indexOf('Appendix A.  Test Vectors'), text.indexOf('Appendix B.'))
  .split('\n')
  .filter((l) => !l.includes('\f') && !/^RFC 5869|\[Page \d+\]$/.test(l))
  .join('\n');
const cases = appendix.split(/\nA\.\d+\.\s+Test Case \d+\n/).slice(1);
const hex = (field: string, block: string): string => {
  const m = new RegExp(
    `^   ${field}\\s*=\\s*(?:0x([0-9a-f\\s]*?)\\s*\\(\\d+ octets\\)|\\(0 octets\\)|not provided)`,
    'm',
  ).exec(block);
  if (!m) throw new Error(`field ${field} not found`);
  return (m[1] ?? '').replace(/\s+/g, '');
};
const out = cases.map((block, i) => {
  const hash = /Hash = (SHA-\d+)/.exec(block)?.[1];
  const length = Number(/L\s+= (\d+)/.exec(block)?.[1]);
  return {
    name: `A.${i + 1}`,
    hash,
    ikm: hex('IKM', block),
    salt: hex('salt', block),
    info: hex('info', block),
    length,
    prk: hex('PRK', block),
    okm: hex('OKM', block),
  };
});
writeFileSync(output, `${JSON.stringify(out, null, 2)}\n`);
