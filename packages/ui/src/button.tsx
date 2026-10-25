import { Button as BaseButton } from '@base-ui/react/button';
import { cva, type VariantProps } from 'class-variance-authority';
import type { ComponentProps } from 'react';
import { cn } from './cn.ts';

// Source: https://ui.shadcn.com/docs/components/base/button and https://base-ui.com/react/components/button
const buttonVariants = cva(
  'inline-flex min-h-11 items-center justify-center gap-2 rounded-md px-4 text-base font-semibold focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-fg disabled:opacity-60',
  {
    variants: {
      variant: {
        primary: 'bg-primary text-primary-fg',
        outline: 'border-2 border-line bg-bg text-fg',
      },
    },
    defaultVariants: { variant: 'primary' },
  },
);

export type ButtonProps = ComponentProps<typeof BaseButton> & VariantProps<typeof buttonVariants>;

export function Button({ className, variant, ...props }: ButtonProps) {
  return <BaseButton className={cn(buttonVariants({ variant }), className as string | undefined)} {...props} />;
}
