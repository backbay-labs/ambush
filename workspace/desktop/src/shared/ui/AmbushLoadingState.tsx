import { cn } from "@/shared/lib/cn";
import { AmbushLogoMotion } from "@/shared/ui/ambush-logo/AmbushLogoMotion";

/** Centered, low-emphasis loading state for page and panel fetches. */
export function AmbushLoadingState({
  className,
  fill = false,
  label = "Loading",
}: {
  className?: string;
  fill?: boolean;
  label?: string;
}) {
  return (
    <div
      className={cn(
        "flex w-full items-center justify-center text-muted-foreground",
        fill ? "min-h-0 flex-1" : "min-h-[calc(100dvh-7rem)]",
        className,
      )}
      data-testid="ambush-loading-state"
      role="status"
    >
      <span aria-label={label} className="block w-8" role="img">
        <AmbushLogoMotion />
      </span>
    </div>
  );
}
