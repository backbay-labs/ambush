import type * as React from "react";

/**
 * Where a number came from.
 *
 * Two markers, never one. A number this console COMPUTED and a number the
 * daemon SERVED can disagree, and when they do an operator must be able to
 * tell which they are reading without opening a table. The marker is the
 * cheapest possible way to say it and it is always rendered.
 */
export function DerivedMarker(): React.ReactElement {
  return (
    <span
      data-testid="perch-derived-marker"
      className="text-2xs text-muted-foreground"
    >
      derived
    </span>
  );
}

export function ServedMarker({ route }: { route: string }): React.ReactElement {
  return (
    <span
      data-testid="perch-served-marker"
      className="text-2xs text-muted-foreground"
    >
      {`served · ${route}`}
    </span>
  );
}
