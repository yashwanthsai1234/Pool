import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

// Source: https://ui.shadcn.com/docs/installation/manual (the `cn` helper)
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
