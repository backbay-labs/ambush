import { cn } from "@/shared/lib/cn";
import { AmbushMark } from "./AmbushMark";

/**
 * The mark seated at the wordmark's left edge, the position the index line
 * occupies against a record everywhere else in the product. The mark's frame
 * carries one stroke width of clear space on each side, so the rule never
 * touches the A; both are sized from the wordmark's own em, and both render in
 * `currentColor`.
 */
export function AmbushLockup({ className }: { className?: string }) {
  return (
    <div
      aria-label="Ambush"
      className={cn(
        "flex items-center font-semibold uppercase leading-none tracking-[0.08em]",
        className,
      )}
      role="img"
    >
      <AmbushMark className="h-[1em] w-[1em] shrink-0" />
      <span>Ambush</span>
    </div>
  );
}
