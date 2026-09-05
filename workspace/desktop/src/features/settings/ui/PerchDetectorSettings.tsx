import type * as React from "react";

import { PerchOperatorKeyPanel } from "./PerchOperatorKeyPanel";
import { PerchSidecarPanel } from "./PerchSidecarPanel";

/**
 * The detector section: this console's decision key, and the laptop demo's
 * locally supervised daemon. Behind the `perch` preview feature like every
 * other perch surface; the panels existed before this section did and were
 * mounted nowhere.
 */
export function PerchDetectorSettings(): React.ReactElement {
  return (
    <div data-testid="perch-detector-settings" className="divide-y">
      <PerchOperatorKeyPanel />
      <PerchSidecarPanel />
    </div>
  );
}
