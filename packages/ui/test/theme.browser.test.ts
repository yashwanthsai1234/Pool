import { describe, expect, it } from 'vitest';
import theme from '../src/theme.css?raw';

function tokens(selector: RegExp): Record<string, string> {
  const block = theme.match(selector)?.[1] ?? '';
  return Object.fromEntries(
    [...block.matchAll(/--([\w-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1] as string, m[2] as string]),
  );
}

// Source: https://www.w3.org/TR/WCAG22/#dfn-contrast-ratio
function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = Number.parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

describe('theme contrast', () => {
  const textTokens = ['fg', 'muted', 'pass', 'fail', 'primary'];
  for (const [name, selector, min] of [
    ['projector', /\[data-theme=['"]projector['"]\]\s*\{([^}]*)\}/, 7],
    ['phone', /:root\s*\{([^}]*)\}/, 4.5],
  ] as const) {
    const t = tokens(selector);
    for (const token of textTokens) {
      it(`${name}: ${token} on bg is at least ${min}:1`, () => {
        expect(t[token], `${token} defined`).toBeDefined();
        expect(contrast(t[token] as string, t.bg as string)).toBeGreaterThanOrEqual(min);
      });
    }
    it(`${name}: primary-fg on primary is at least ${min}:1`, () => {
      expect(contrast(t['primary-fg'] as string, t.primary as string)).toBeGreaterThanOrEqual(min);
    });
    it(`${name}: line (non-text boundary) is at least 3:1`, () => {
      expect(contrast(t.line as string, t.bg as string)).toBeGreaterThanOrEqual(3);
    });
  }
});
