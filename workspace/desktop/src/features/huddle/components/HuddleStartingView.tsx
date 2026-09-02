import { AmbushLogoMotion } from "@/shared/ui/ambush-logo/AmbushLogoMotion";

/** Immediate feedback shown while the native huddle session is being prepared. */
export function HuddleStartingView() {
  return (
    <div
      aria-label="Starting huddle"
      className="ambush-setup-loading-shell flex min-h-0 flex-1 items-center justify-center px-6 text-foreground"
      data-testid="huddle-starting-view"
      role="status"
    >
      <span className="sr-only">Starting huddle</span>
      <AmbushLogoMotion className="h-auto w-28" />
    </div>
  );
}
