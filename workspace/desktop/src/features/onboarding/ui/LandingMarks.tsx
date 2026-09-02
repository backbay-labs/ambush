import { AmbushMark } from "@/shared/ui/ambush-logo/AmbushMark";

/** The landing carries the mark once, in the position the chrome holds it. */
export function LandingMarks() {
  return (
    <div aria-hidden className="pointer-events-none absolute inset-0">
      <span className="absolute left-6 top-12 block w-11 text-foreground">
        <AmbushMark className="h-auto w-full" />
      </span>
    </div>
  );
}
