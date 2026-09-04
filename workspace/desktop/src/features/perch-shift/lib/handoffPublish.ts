/**
 * Publishing the END WATCH block into every touched case.
 *
 * Per-channel, and the outcome is per-channel: a handoff that reached four of
 * six case channels has to say four of six, because the two it missed are the
 * cases whose next operator will not see the note. A boolean here would let a
 * partial publish read as a whole one.
 *
 * Failures do not roll back what already published. There is nothing to roll
 * back to — a message in a case channel has been read by whoever was watching
 * it — and deleting the successful ones to make the result uniform would
 * destroy the only handoff that worked.
 */

export type HandoffPublishOutcome = {
  published: string[];
  failed: { channelId: string; reason: string }[];
};

export async function publishHandoff(
  channelIds: string[],
  notes: string,
  send: (channelId: string, content: string) => Promise<unknown>,
): Promise<HandoffPublishOutcome> {
  const published: string[] = [];
  const failed: { channelId: string; reason: string }[] = [];
  for (const channelId of channelIds) {
    try {
      await send(channelId, notes);
      published.push(channelId);
    } catch (error) {
      failed.push({
        channelId,
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return { published, failed };
}
