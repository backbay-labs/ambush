import * as React from "react";

import {
  type PerchOperatorIdentity,
  perchOperatorIdentity,
} from "@/shared/api/tauriPerch";

/**
 * The public half of this console's decision key.
 *
 * The daemon checks every hold decision against a key it pins per principal,
 * and until this key is pasted into that entry every decision this console
 * signs is refused as unknown. Nothing here ever holds the seed: the Tauri
 * side derives the public half and returns only that.
 */
export function PerchOperatorKeyPanel(): React.ReactElement {
  const [identity, setIdentity] = React.useState<PerchOperatorIdentity | null>(
    null,
  );
  const [error, setError] = React.useState<string | null>(null);
  const [copied, setCopied] = React.useState(false);

  React.useEffect(() => {
    let cancelled = false;
    perchOperatorIdentity()
      .then((next) => {
        if (!cancelled) setIdentity(next);
      })
      .catch((cause: unknown) => {
        if (!cancelled)
          setError(cause instanceof Error ? cause.message : String(cause));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const onCopy = React.useCallback(async () => {
    if (identity === null) return;
    try {
      await navigator.clipboard.writeText(identity.public_key_hex);
      setCopied(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [identity]);

  return (
    <section data-testid="perch-operator-key-panel" className="p-4">
      <h3 className="text-sm font-medium">Decision key</h3>
      <p className="mt-1 text-xs text-muted-foreground">
        The daemon checks every hold decision against this key. Paste the public
        half into the daemon&apos;s principal entry as{" "}
        <code>verdict_public_key_hex</code>; until a daemon pins it, decisions
        from here are refused as unknown.
      </p>
      {identity !== null ? (
        <>
          <p
            data-testid="perch-operator-key"
            className="mt-2 break-all font-mono text-xs"
          >
            {identity.public_key_hex}
          </p>
          <p
            data-testid="perch-operator-key-id"
            className="mt-1 break-all text-2xs text-muted-foreground"
          >
            {`key id ${identity.key_id}`}
          </p>
          <button
            type="button"
            data-testid="perch-operator-key-copy"
            className="mt-2 rounded border border-border px-2 py-1 text-sm"
            onClick={() => void onCopy()}
          >
            {copied ? "Copied" : "Copy public key"}
          </button>
        </>
      ) : error === null ? (
        <p data-testid="perch-operator-key-loading" className="mt-2 text-sm">
          Reading the key from the keyring…
        </p>
      ) : null}
      {error !== null ? (
        <p data-testid="perch-operator-key-error" className="mt-2 text-sm">
          {error}
        </p>
      ) : null}
    </section>
  );
}
