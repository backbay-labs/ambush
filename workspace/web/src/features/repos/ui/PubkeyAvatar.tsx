import { Tooltip, TooltipContent, TooltipTrigger } from "@/shared/ui/tooltip";

const AVATAR_RAMP = [
  "bg-night text-ink",
  "bg-steel text-ink",
  "bg-rule text-ink",
  "bg-grad text-night",
  "bg-plate text-ink",
  "bg-plate-hi text-ink",
  "bg-ink-dim text-night",
];

/** Hash of a hex pubkey to a step on the identity ramp. */
function pubkeyToRampIndex(hex: string): number {
  let hash = 0;
  for (let i = 0; i < hex.length; i++) {
    hash = (hash * 31 + hex.charCodeAt(i)) | 0;
  }
  return Math.abs(hash) % AVATAR_RAMP.length;
}

export function PubkeyAvatar({
  pubkey,
  size = "md",
}: {
  pubkey: string;
  size?: "sm" | "md";
}) {
  const ramp = AVATAR_RAMP[pubkeyToRampIndex(pubkey)];
  const sizeClasses = size === "sm" ? "h-6 w-6 text-2xs" : "h-8 w-8 text-xs";

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div
          className={`flex items-center justify-center rounded-lg font-medium ${ramp} ${sizeClasses}`}
        >
          {pubkey.slice(0, 2)}
        </div>
      </TooltipTrigger>
      <TooltipContent>
        <span className="font-mono text-xs">{pubkey}</span>
      </TooltipContent>
    </Tooltip>
  );
}
