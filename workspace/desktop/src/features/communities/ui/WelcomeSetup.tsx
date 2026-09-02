import * as React from "react";
import { Check, Copy } from "lucide-react";

import {
  canOfferConfiguredCommunity,
  type ConfiguredCommunity,
  resolveConfiguredCommunity,
} from "@/features/communities/configuredCommunity";
import { HostedCommunityOnboarding } from "@/features/communities/ui/HostedCommunityOnboarding";
import { useCommunityOnboarding } from "@/features/onboarding/communityOnboarding";
import { InviteRedeemForm } from "@/features/onboarding/ui/InviteRedeemForm";
import { OnboardingChrome } from "@/features/onboarding/ui/OnboardingChrome";
import { OnboardingFooterProvider } from "@/features/onboarding/ui/OnboardingFooter";
import {
  type OnboardingTransitionDirection,
  OnboardingSlideTransition,
} from "@/features/onboarding/ui/OnboardingSlideTransition";
import { useIdentityQuery } from "@/shared/api/hooks";
import { writeTextToClipboard } from "@/shared/lib/clipboard";
import { pubkeyToNpub } from "@/shared/lib/nostrUtils";
import { useSystemColorScheme } from "@/shared/theme/useSystemColorScheme";
import { Button } from "@/shared/ui/button";
import { Card } from "@/shared/ui/card";
import { StartupWindowDragRegion } from "@/shared/ui/StartupWindowDragRegion";

type WelcomeSetupPage = "welcome" | "existing" | "join" | "member" | "owned";
type WelcomeTransitionMode = "initial" | OnboardingTransitionDirection;

type WelcomeSetupProps = {
  /** Relay this instance is configured to use, offered as the first option. */
  defaultRelayUrl?: string;
  initialPage?: WelcomeSetupPage;
  initialTransitionMode?: WelcomeTransitionMode;
  onBack?: () => void;
};

// A plate option: hover is a step up in lightness, never a glow.
const COMMUNITY_OPTION_CARD_CLASS =
  "flex min-h-[5.5rem] w-full max-w-[320px] flex-col items-center justify-center border-border bg-card px-6 py-4 text-center text-sm font-normal leading-6 text-foreground transition-colors duration-150 ease-out hover:bg-accent focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-foreground/35";

export function WelcomeSetup({
  defaultRelayUrl,
  initialPage = "welcome",
  initialTransitionMode = "initial",
  onBack,
}: WelcomeSetupProps) {
  const [page, setPage] = React.useState<WelcomeSetupPage>(initialPage);
  const [transitionMode, setTransitionMode] =
    React.useState<WelcomeTransitionMode>(initialTransitionMode);
  // While true, the Builderlab sign-in modal floats over the current page —
  // we only navigate to the hosted stage once sign-in completes, so the page
  // behind the modal never changes out from under the user.
  const [isHostedSignInOpen, setIsHostedSignInOpen] = React.useState(false);
  const [copiedNpub, setCopiedNpub] = React.useState(false);
  const [configuredCommunity, setConfiguredCommunity] =
    React.useState<ConfiguredCommunity | null>(null);
  const communityOnboarding = useCommunityOnboarding();
  const identityQuery = useIdentityQuery();
  const systemColorScheme = useSystemColorScheme();
  const npub = identityQuery.data?.pubkey
    ? pubkeyToNpub(identityQuery.data.pubkey)
    : "";
  const npubError = identityQuery.error
    ? identityQuery.error instanceof Error
      ? identityQuery.error.message
      : "Could not load your public key."
    : null;

  // Dev instances are always pointed at a relay, so the community the user is
  // here to reach is already known. Offer it once it answers for itself.
  React.useEffect(() => {
    if (!defaultRelayUrl || !canOfferConfiguredCommunity()) return;
    let cancelled = false;
    void resolveConfiguredCommunity(defaultRelayUrl).then((resolved) => {
      if (!cancelled) setConfiguredCommunity(resolved);
    });
    return () => {
      cancelled = true;
    };
  }, [defaultRelayUrl]);

  const showPage = React.useCallback(
    (nextPage: WelcomeSetupPage, direction?: OnboardingTransitionDirection) => {
      setTransitionMode(
        direction ?? (nextPage === "welcome" ? "backward" : "forward"),
      );
      setPage(nextPage);
    },
    [],
  );

  const startConnection = React.useCallback(
    (relayUrl: string) => {
      communityOnboarding.start({
        source: "first-community",
        firstCommunityPage:
          page === "member"
            ? "member"
            : page === "welcome"
              ? "welcome"
              : "join",
        relayUrl,
      });
    },
    [communityOnboarding, page],
  );

  const redeemInvite = React.useCallback(
    (relayUrl: string, code: string, policyReceipt?: string) => {
      communityOnboarding.start({
        source: "first-community",
        firstCommunityPage: page === "member" ? "member" : "join",
        relayUrl,
        inviteCode: code,
        policyReceipt,
      });
    },
    [communityOnboarding, page],
  );

  const beginHostedCommunity = React.useCallback(
    () => setIsHostedSignInOpen(true),
    [],
  );

  const transitionDirection =
    transitionMode === "backward" ? "backward" : "forward";
  const backAction =
    page === "welcome" && onBack
      ? { onClick: onBack, testId: "welcome-setup-back" }
      : page === "existing"
        ? {
            onClick: () => showPage("welcome"),
            testId: "existing-back",
          }
        : page === "join"
          ? {
              onClick: () => showPage("welcome"),
              testId: "welcome-join-back",
            }
          : page === "member"
            ? {
                onClick: () => showPage("existing"),
                testId: "welcome-member-back",
              }
            : undefined;

  return (
    <div
      className="ambush-onboarding-neutral-theme ambush-startup-shell flex h-dvh items-start justify-center overflow-y-auto bg-background px-4 pb-36 pt-[106px] text-foreground"
      data-system-color-scheme={systemColorScheme}
      data-testid="welcome-setup"
    >
      <StartupWindowDragRegion />
      <OnboardingChrome current={5} />
      <OnboardingFooterProvider backAction={backAction}>
        <div className="relative flex min-h-0 w-full max-w-[920px] flex-1 flex-col items-center text-center">
          {page === "welcome" ? (
            <OnboardingSlideTransition
              className="flex h-full min-h-0 w-full flex-col items-center text-center"
              containerClassName="h-full min-h-0 [&>.ambush-onboarding-transition-line]:h-full"
              direction={transitionDirection}
              transitionKey={`welcome-${transitionDirection}`}
            >
              <div className="w-full max-w-[760px]">
                <h1 className="text-title font-normal">
                  Join or create a community
                </h1>
                <p className="mt-3 text-sm leading-6 text-foreground/80">
                  Join with an invite, create your own community, or reconnect
                  one you already have.
                </p>
              </div>
              <div className="flex w-full flex-1 flex-col items-center justify-center gap-4 py-8">
                {configuredCommunity ? (
                  <Card asChild className={COMMUNITY_OPTION_CARD_CLASS}>
                    <button
                      data-testid="community-choice-configured"
                      onClick={() =>
                        startConnection(configuredCommunity.relayUrl)
                      }
                      type="button"
                    >
                      <span>Reconnect to {configuredCommunity.name}</span>
                      <span className="mt-1 break-words font-mono text-xs text-foreground/60">
                        {configuredCommunity.relayUrl}
                      </span>
                    </button>
                  </Card>
                ) : null}
                <Card asChild className={COMMUNITY_OPTION_CARD_CLASS}>
                  <button
                    data-testid="community-choice-join"
                    onClick={() => showPage("join")}
                    type="button"
                  >
                    Join a community
                  </button>
                </Card>
                <Card asChild className={COMMUNITY_OPTION_CARD_CLASS}>
                  <button
                    data-testid="community-choice-create"
                    onClick={beginHostedCommunity}
                    type="button"
                  >
                    Create a community
                  </button>
                </Card>
                <Card asChild className={COMMUNITY_OPTION_CARD_CLASS}>
                  <button
                    data-testid="community-choice-existing"
                    onClick={() => showPage("existing")}
                    type="button"
                  >
                    I already have a community
                  </button>
                </Card>
              </div>
            </OnboardingSlideTransition>
          ) : page === "existing" ? (
            <OnboardingSlideTransition
              className="flex h-full min-h-0 w-full flex-col items-center text-center"
              containerClassName="h-full min-h-0 [&>.ambush-onboarding-transition-line]:h-full"
              direction={transitionDirection}
              transitionKey={`existing-${transitionDirection}`}
            >
              <div className="w-full max-w-[760px]">
                <h1 className="text-title font-normal">
                  Reconnect to your community
                </h1>
                <p className="mt-3 text-sm leading-6 text-foreground/80">
                  Tell us your role so we can find the fastest way back in.
                </p>
              </div>
              <div className="flex w-full flex-1 flex-col items-center justify-center gap-4 py-8">
                <Card asChild className={COMMUNITY_OPTION_CARD_CLASS}>
                  <button
                    data-testid="existing-choice-owner"
                    onClick={beginHostedCommunity}
                    type="button"
                  >
                    I own the community
                  </button>
                </Card>
                <Card asChild className={COMMUNITY_OPTION_CARD_CLASS}>
                  <button
                    data-testid="existing-choice-member"
                    onClick={() => showPage("member")}
                    type="button"
                  >
                    I’m a member or admin
                  </button>
                </Card>
              </div>
            </OnboardingSlideTransition>
          ) : page === "owned" ? (
            <OnboardingSlideTransition
              className="flex w-full flex-col items-center text-center"
              direction={transitionDirection}
              transitionKey={`owned-${transitionDirection}`}
            >
              <HostedCommunityOnboarding onBack={() => showPage("welcome")} />
            </OnboardingSlideTransition>
          ) : (
            <OnboardingSlideTransition
              className="flex min-h-[calc(100dvh-15.625rem)] w-full flex-col items-center text-center"
              direction={transitionDirection}
              transitionKey={`${page}-${transitionDirection}`}
            >
              <div className="w-full max-w-[620px]">
                <h1 className="text-title font-normal">
                  {page === "member"
                    ? "Reconnect to your community"
                    : "Join a community"}
                </h1>
                <p className="mt-3 text-sm leading-6 text-foreground/80">
                  {page === "member"
                    ? "Enter the community URL or an invite link. Your role will be restored when you connect."
                    : "Enter the invite link or community URL you received."}
                </p>
              </div>
              <div className="flex w-full flex-1 flex-col items-center justify-center gap-16">
                <InviteRedeemForm
                  error={null}
                  initialValue={
                    page === "member" && configuredCommunity
                      ? configuredCommunity.relayUrl
                      : undefined
                  }
                  isRedeeming={false}
                  onCancel={() =>
                    showPage(page === "member" ? "existing" : "welcome")
                  }
                  onConnect={startConnection}
                  onRedeem={redeemInvite}
                  placeholder="Invite link or community URL"
                  variant="onboarding-spotlight"
                />
                {page === "join" ? (
                  <div className="w-full max-w-[560px] text-left">
                    <p className="text-sm font-medium text-foreground">
                      Joining a private community?
                    </p>
                    <p className="mt-2 text-sm leading-6 text-foreground/75">
                      Some communities need the owner to add you before you can
                      join. Copy your public ID and send it to the community
                      owner.
                    </p>
                    <div className="mt-4 flex items-center gap-3 rounded-xl border border-foreground/10 bg-background/35 px-4 py-3">
                      <code
                        className="min-w-0 flex-1 truncate font-mono text-xs text-foreground/80"
                        data-testid="welcome-join-npub"
                      >
                        {npub || "Loading…"}
                      </code>
                      <Button
                        aria-label="Copy public ID"
                        className="h-9 shrink-0 rounded-full px-3"
                        disabled={!npub}
                        onClick={() => {
                          void writeTextToClipboard(npub).then(() => {
                            setCopiedNpub(true);
                            window.setTimeout(() => setCopiedNpub(false), 1500);
                          });
                        }}
                        size="sm"
                        type="button"
                        variant="outline"
                      >
                        {copiedNpub ? (
                          <Check className="h-4 w-4" aria-hidden="true" />
                        ) : (
                          <Copy className="h-4 w-4" aria-hidden="true" />
                        )}
                        <span>{copiedNpub ? "Copied" : "Copy"}</span>
                      </Button>
                    </div>
                    {npubError ? (
                      <p className="mt-3 text-sm text-destructive">
                        {npubError}
                      </p>
                    ) : null}
                  </div>
                ) : null}
              </div>
            </OnboardingSlideTransition>
          )}
          {isHostedSignInOpen && page !== "owned" ? (
            <HostedCommunityOnboarding
              onBack={() => setIsHostedSignInOpen(false)}
              onReady={() => {
                setIsHostedSignInOpen(false);
                showPage("owned");
              }}
              stageHidden
            />
          ) : null}
        </div>
      </OnboardingFooterProvider>
    </div>
  );
}
