import ambushAppIcon from "@/assets/app-icon@3x.png";
import { claimInviteInBrowser } from "@/features/invite/invite-api";
import {
  AMBUSH_RELEASES_URL,
  type AmbushDownloadPlatform,
  detectAmbushDownloadPlatform,
  resolveAmbushDownloadUrlForPlatform,
} from "@/shared/lib/ambush-download";
import { hasNip07Provider } from "@/shared/lib/nostr-signer";
import { relayWsUrl } from "@/shared/lib/relay-url";
import { Button } from "@/shared/ui/button";
import { AlertTriangle } from "lucide-react";
import * as React from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { InviteJoinPolicyNotice } from "./InviteJoinPolicyNotice";

type JoinPolicy = {
  terms_markdown?: string;
  privacy_markdown?: string;
  age_attestation_required: boolean;
  version: string;
};

type PolicyDocument = { title: string; markdown: string };

/** Convert relay invite sentinels into user-facing recovery guidance. */
function inviteClaimErrorMessage(message: string): string {
  if (message.includes("invite_exhausted")) {
    return "This invite has reached its use limit. Ask for a new invite.";
  }
  if (message.includes("invite_expired")) {
    return "This invite has expired. Ask for a new invite.";
  }
  if (message.includes("invite_invalid")) {
    return "This invite is invalid. Check the link or ask for a new invite.";
  }
  return message;
}

/** Landing page for a community invite link (`/invite/<code>`). */
export function InvitePage({ code }: { code: string }) {
  const relay = relayWsUrl();
  const host = relay.replace(/^wss?:\/\//, "");
  const [policy, setPolicy] = React.useState<JoinPolicy | null | undefined>(
    undefined,
  );
  const [document, setDocument] = React.useState<PolicyDocument | null>(null);
  const [ageConfirmed, setAgeConfirmed] = React.useState(false);
  const [agreementConfirmed, setAgreementConfirmed] = React.useState(false);
  const [opening, setOpening] = React.useState(false);
  const [joiningBrowser, setJoiningBrowser] = React.useState(false);
  const [browserJoinError, setBrowserJoinError] = React.useState<string | null>(
    null,
  );
  const [downloadUrl, setDownloadUrl] = React.useState(AMBUSH_RELEASES_URL);
  const [needsMacChoice, setNeedsMacChoice] = React.useState(false);
  const [showMacChoice, setShowMacChoice] = React.useState(false);
  const [choosingMacDownload, setChoosingMacDownload] = React.useState(false);
  const choosingMacDownloadRef = React.useRef(false);
  const downloadTriggerRef = React.useRef<HTMLAnchorElement>(null);

  React.useEffect(() => {
    let active = true;
    detectAmbushDownloadPlatform(navigator).then(async (platform) => {
      if (!active) return;
      if (
        platform.operatingSystem === "macos" &&
        platform.architecture === "unknown"
      ) {
        setNeedsMacChoice(true);
        return;
      }
      const url = await resolveAmbushDownloadUrlForPlatform(platform);
      if (active) setDownloadUrl(url);
    });
    return () => {
      active = false;
    };
  }, []);

  React.useEffect(() => {
    fetch("/api/join-policy")
      .then(async (response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const config = (await response.json()) as { policy?: JoinPolicy };
        setPolicy(config.policy ?? null);
      })
      .catch(() => setPolicy(undefined));
  }, []);

  const acceptPolicy = async (): Promise<string | undefined> => {
    if (!policy) return undefined;
    const response = await fetch("/api/invites/accept-policy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        policy_version: policy.version,
        age_confirmed: ageConfirmed,
      }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return ((await response.json()) as { receipt: string }).receipt;
  };

  const openInvite = async () => {
    setOpening(true);
    try {
      const receipt = await acceptPolicy();
      const query = new URLSearchParams({ relay, code });
      if (receipt) query.set("policy_receipt", receipt);
      window.location.href = `ambush://join?${query.toString()}`;
    } finally {
      setOpening(false);
    }
  };

  const joinInBrowser = async () => {
    setBrowserJoinError(null);
    setJoiningBrowser(true);
    try {
      const receipt = await acceptPolicy();
      await claimInviteInBrowser(code, receipt);
      window.location.assign("/");
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Could not claim this invite.";
      setBrowserJoinError(inviteClaimErrorMessage(message));
    } finally {
      setJoiningBrowser(false);
    }
  };

  const browserSigningAvailable = hasNip07Provider();
  const disabled =
    policy === undefined ||
    opening ||
    joiningBrowser ||
    Boolean(policy?.age_attestation_required && !ageConfirmed) ||
    Boolean(
      policy &&
        (policy.terms_markdown || policy.privacy_markdown) &&
        !agreementConfirmed,
    );
  const hasPolicyRequirements = Boolean(
    policy &&
      (policy.age_attestation_required ||
        policy.terms_markdown ||
        policy.privacy_markdown),
  );
  const showDocument = (title: string, markdown: string) =>
    setDocument({ title, markdown });
  const closeMacChoice = React.useCallback(() => {
    setShowMacChoice(false);
    window.setTimeout(() => downloadTriggerRef.current?.focus());
  }, []);
  const chooseMacDownload = async (
    event: React.MouseEvent<HTMLAnchorElement>,
    platform: AmbushDownloadPlatform,
  ) => {
    event.preventDefault();
    if (choosingMacDownloadRef.current) return;
    choosingMacDownloadRef.current = true;
    setChoosingMacDownload(true);
    const downloadWindow = window.open("about:blank", "_blank");
    if (downloadWindow) downloadWindow.opener = null;
    setShowMacChoice(false);
    try {
      const url = await resolveAmbushDownloadUrlForPlatform(platform);
      downloadWindow?.location.replace(url);
    } finally {
      choosingMacDownloadRef.current = false;
      setChoosingMacDownload(false);
    }
  };

  React.useEffect(() => {
    if (!showMacChoice) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeMacChoice();
    };
    window.document.addEventListener("keydown", closeOnEscape);
    return () => window.document.removeEventListener("keydown", closeOnEscape);
  }, [closeMacChoice, showMacChoice]);

  return (
    <div className="flex flex-1 flex-col items-center justify-center bg-background px-4 py-16 text-center">
      <div className="w-full max-w-xl space-y-4">
        <div className="flex w-full flex-col items-center rounded-3xl bg-card px-6 py-10 text-card-foreground sm:px-12 sm:py-12">
          <div
            className="h-12 w-12 overflow-hidden bg-night"
            style={{ borderRadius: "22.37%" }}
          >
            <img alt="Ambush" className="h-full w-full" src={ambushAppIcon} />
          </div>
          <h1 className="mt-4 text-2xl font-semibold tracking-tight">
            You&apos;re invited to
          </h1>
          <p className="mt-9 font-mono text-lg text-muted-foreground">{host}</p>

          <div
            className={`grid w-full max-w-md overflow-hidden transition-[grid-template-rows,margin,opacity,transform] duration-[220ms] [transition-timing-function:cubic-bezier(0.23,1,0.32,1)] motion-reduce:transition-none ${
              hasPolicyRequirements
                ? "mt-9 -mb-4 grid-rows-[1fr] opacity-100 translate-y-0"
                : "m-0 grid-rows-[0fr] opacity-0 -translate-y-1"
            }`}
          >
            <div className="min-h-0 overflow-hidden">
              {policy && hasPolicyRequirements ? (
                <InviteJoinPolicyNotice
                  ageConfirmed={ageConfirmed}
                  agreementConfirmed={agreementConfirmed}
                  onAgeConfirmedChange={setAgeConfirmed}
                  onAgreementConfirmedChange={setAgreementConfirmed}
                  onShowDocument={showDocument}
                  policy={policy}
                />
              ) : null}
            </div>
          </div>

          <div className="mt-9 w-full max-w-md space-y-2">
            {browserSigningAvailable ? (
              <Button
                className="h-10 w-full disabled:cursor-not-allowed"
                disabled={disabled}
                onClick={joinInBrowser}
              >
                {joiningBrowser ? "Joining…" : "Join in browser"}
              </Button>
            ) : null}
            {policy === null ? (
              <Button
                asChild
                variant={browserSigningAvailable ? "outline" : "default"}
                className="h-10 w-full"
              >
                <a
                  href={`ambush://join?relay=${encodeURIComponent(relay)}&code=${encodeURIComponent(code)}`}
                >
                  Accept invite in Ambush
                </a>
              </Button>
            ) : (
              <Button
                variant={browserSigningAvailable ? "outline" : "default"}
                className="h-10 w-full disabled:cursor-not-allowed"
                disabled={disabled}
                onClick={openInvite}
              >
                Accept invite in Ambush
              </Button>
            )}
            {browserJoinError ? (
              <p
                className="flex items-center justify-center gap-1.5 text-sm text-foreground"
                role="alert"
              >
                <AlertTriangle className="h-4 w-4 shrink-0" />
                {browserJoinError}
              </p>
            ) : null}
          </div>
        </div>
        <p className="flex h-[3.125rem] items-center justify-center rounded-2xl bg-card text-sm text-muted-foreground">
          Don&apos;t have the app?{" "}
          <a
            aria-expanded={needsMacChoice ? showMacChoice : undefined}
            aria-haspopup={needsMacChoice ? "dialog" : undefined}
            className="ml-1 font-medium text-foreground underline-offset-4 hover:text-muted-foreground hover:underline focus-visible:underline"
            href={downloadUrl}
            ref={downloadTriggerRef}
            rel="noreferrer"
            target="_blank"
            onClick={(event) => {
              if (!needsMacChoice) return;
              event.preventDefault();
              setShowMacChoice(true);
            }}
          >
            Download it now
          </a>
        </p>
      </div>

      {showMacChoice && (
        <div
          aria-label="Which Mac do you have?"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 text-left"
          role="dialog"
          onMouseDown={(event) => {
            if (event.currentTarget === event.target) closeMacChoice();
          }}
        >
          <div className="w-full max-w-lg rounded-3xl bg-card p-7 text-card-foreground shadow-xl sm:p-9">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 className="text-2xl font-semibold tracking-tight">
                  Which Mac do you have?
                </h2>
                <p className="mt-2 text-sm text-muted-foreground">
                  Choose based on when your Mac was released.
                </p>
              </div>
              <button
                aria-label="Close"
                className="text-2xl leading-none text-muted-foreground hover:text-foreground"
                type="button"
                onClick={closeMacChoice}
              >
                ×
              </button>
            </div>
            <div className="mt-6 grid gap-3">
              <a
                aria-disabled={choosingMacDownload}
                className="rounded-2xl border border-border p-5 no-underline hover:bg-accent hover:text-accent-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring aria-disabled:pointer-events-none aria-disabled:opacity-50"
                href={AMBUSH_RELEASES_URL}
                onClick={(event) =>
                  void chooseMacDownload(event, {
                    operatingSystem: "macos",
                    architecture: "arm64",
                  })
                }
              >
                <strong className="block text-lg">Newer Mac</strong>
                <span className="mt-1 block text-sm">
                  2021 or later, or a late-2020 Mac with an Apple M1 chip
                </span>
              </a>
              <a
                aria-disabled={choosingMacDownload}
                className="rounded-2xl border border-border p-5 no-underline hover:bg-accent hover:text-accent-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring aria-disabled:pointer-events-none aria-disabled:opacity-50"
                href={AMBUSH_RELEASES_URL}
                onClick={(event) =>
                  void chooseMacDownload(event, {
                    operatingSystem: "macos",
                    architecture: "x64",
                  })
                }
              >
                <strong className="block text-lg">Older Mac</strong>
                <span className="mt-1 block text-sm">
                  2019 or earlier, or a 2020 Mac with an Intel processor
                </span>
              </a>
            </div>
            <p className="mt-5 text-sm leading-5">
              <strong>Not sure?</strong> Open the Apple menu and choose{" "}
              <strong>About This Mac</strong>. “Chip: Apple M…” means Newer Mac.
              “Processor: Intel” means Older Mac.
            </p>
          </div>
        </div>
      )}

      {document && (
        <div
          aria-label={document.title}
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 text-left"
          role="dialog"
          onMouseDown={(event) => {
            if (event.currentTarget === event.target) setDocument(null);
          }}
        >
          <div className="max-h-[85vh] w-full max-w-3xl overflow-y-auto rounded-2xl bg-card p-6 text-card-foreground shadow-xl sm:p-8">
            <div className="mb-6 flex items-start justify-between gap-4">
              <h2 className="text-xl font-semibold">{document.title}</h2>
              <button
                aria-label="Close"
                className="text-2xl leading-none text-muted-foreground hover:text-foreground"
                type="button"
                onClick={() => setDocument(null)}
              >
                ×
              </button>
            </div>
            <div className="prose prose-sm max-w-none">
              <Markdown remarkPlugins={[remarkGfm]}>
                {document.markdown}
              </Markdown>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
