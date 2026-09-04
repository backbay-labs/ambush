import { RefreshCcw } from "lucide-react";

import { Button } from "@/shared/ui/button";

type HomeFeedUnavailableProps = {
  errorMessage?: string;
  onRefresh: () => void;
};

export function HomeFeedUnavailable({
  errorMessage,
  onRefresh,
}: HomeFeedUnavailableProps) {
  return (
    <div className="flex-1 overflow-hidden px-4 pb-3 pt-4 sm:px-6">
      <div className="flex w-full max-w-3xl flex-col gap-4">
        <div className="rounded-md border border-destructive/30 bg-destructive/5 px-4 py-5">
          <p className="text-base font-semibold tracking-tight">
            Home feed unavailable
          </p>
          <p className="mt-2 text-sm text-muted-foreground">
            {errorMessage ?? "The relay did not return a feed response."}
          </p>
          <Button className="mt-5" onClick={onRefresh} type="button">
            <RefreshCcw className="h-4 w-4" />
            Try again
          </Button>
        </div>
      </div>
    </div>
  );
}
