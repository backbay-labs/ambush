import { RecoveryScreen } from "./RecoveryScreen";

export function RelaunchRequiredScreen() {
  return (
    <RecoveryScreen
      testId="relaunch-required"
      title="Restart Ambush to finish recovery"
      body="Your identity was updated. Ambush needs to restart so syncing and agents run under it."
    />
  );
}
