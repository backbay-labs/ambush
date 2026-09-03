/**
 * The Ambush mark: an index rule stepped once, at the instant its state
 * changed. Plain static SVG — no SMIL, no scripting — rendered in
 * `currentColor` so it tints per-theme and paints complete on the first frame
 * regardless of animation support.
 */
export function AmbushMark({ className }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={["ambush-mark", className].filter(Boolean).join(" ")}
      viewBox="0 0 256 256"
      fill="currentColor"
    >
      <path d="M64 0h64v152H64z" />
      <path d="M128 136h64v120h-64z" />
    </svg>
  );
}
