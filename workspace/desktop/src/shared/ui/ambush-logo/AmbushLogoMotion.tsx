import "./ambush-logo-animation.css";

/**
 * The Ambush mark with the index engraving in — the live segment inks down
 * from the top, the spent segment follows, both hold, and the cycle repeats.
 * Geometry is identical to the static {@link AmbushMark}, rendered in
 * `currentColor` so it tints per-theme.
 *
 * Each segment is an HTML-level element rather than an SVG child, and the
 * animation drives its CSS transform. This is deliberate: WebKit paints SVG
 * *children* on the main thread, so a transform animation on a `<path>`
 * freezes for as long as boot work (bundle eval, first React render of the app
 * tree) hogs the thread — exactly the window in which the loading gate is on
 * screen. Transforms on HTML-level elements run on the compositor (Core
 * Animation in WKWebView) and keep running regardless.
 *
 * Everything is plain CSS (no JS/SMIL), so it paints on the very first frame.
 * Reduced motion falls back to the static silhouette via the media query.
 */
export function AmbushLogoMotion({ className }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={["ambush-mark", "ambush-index", className]
        .filter(Boolean)
        .join(" ")}
    >
      <span className="ambush-index__seg ambush-index__seg--live" />
      <span className="ambush-index__seg ambush-index__seg--spent" />
    </div>
  );
}
