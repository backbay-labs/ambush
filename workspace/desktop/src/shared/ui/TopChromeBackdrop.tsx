import { cn } from "@/shared/lib/cn";
import { topChromeBackdrop } from "@/shared/layout/chromeLayout";

/**
 * Opaque strip pinned to the top of a scroll container so content scrolls
 * *under* the global search chrome instead of showing through it.
 *
 * Render as the first child of a `relative` (non-scrolling) parent, alongside
 * the scrollable content. It is purely decorative (aria-hidden,
 * pointer-events-none) and sits at z-40 — below the global chrome controls
 * (z-[45]) but above page content.
 *
 * Height follows `--ambush-top-chrome-height` on the app `<main>` inset.
 * Pass `className` to override for panels whose own header occupies the top.
 */
export function TopChromeBackdrop({ className }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={cn(
        "pointer-events-none absolute inset-x-0 top-0 z-40 bg-background after:absolute after:inset-x-0 after:h-px after:bg-border after:content-['']",
        topChromeBackdrop.height,
        topChromeBackdrop.dividerTop,
        className,
      )}
    />
  );
}
