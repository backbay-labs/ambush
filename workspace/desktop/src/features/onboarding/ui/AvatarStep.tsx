import { ProfileAvatar } from "@/features/profile/ui/ProfileAvatar";
import {
  type AvatarMode,
  parseEmojiAvatarDataUrl,
  ProfileAvatarEditor,
} from "@/features/profile/ui/ProfileAvatarEditor";
import { Plus } from "lucide-react";
import { cn } from "@/shared/lib/cn";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";
import { ONBOARDING_PRIMARY_CTA_CLASS } from "./OnboardingChrome";
import { OnboardingFooter } from "./OnboardingFooter";
import { AnimatePresence, motion } from "motion/react";
import * as React from "react";
import {
  type OnboardingTransitionDirection,
  OnboardingSlideTransition,
} from "./OnboardingSlideTransition";
import type { ProfileStepActions, ProfileStepState } from "./types";

type AvatarStepProps = {
  actions: {
    advanceWithoutSaving: ProfileStepActions["advanceWithoutSaving"];
    back: () => void;
    onUploadingChange: ProfileStepActions["onUploadingChange"];
    skipForNow: ProfileStepActions["skipForNow"];
    submit: ProfileStepActions["submit"];
    updateAvatarUrl: ProfileStepActions["updateAvatarUrl"];
  };
  direction: OnboardingTransitionDirection;
  /** When true, a ghost "Skip for now" button is always visible (not just on error). */
  showAlwaysSkip?: boolean;
  showBack?: boolean;
  state: Pick<
    ProfileStepState,
    "avatar" | "isSaving" | "isUploadingAvatar" | "name" | "saveRecovery"
  >;
};

function ErrorBanner({ message }: { message: string | null }) {
  if (!message) {
    return null;
  }

  return (
    <p className="mx-auto mt-4 w-full max-w-[576px] rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
      {message}
    </p>
  );
}

const NEUTRAL_EMOJI_PICKER_THEME_VARS = {
  "--ambush-emoji-picker-rgb-background":
    "var(--ambush-onboarding-emoji-picker-background)",
  "--ambush-emoji-picker-rgb-color":
    "var(--ambush-onboarding-emoji-picker-color)",
  "--ambush-emoji-picker-rgb-input":
    "var(--ambush-onboarding-emoji-picker-input)",
} as React.CSSProperties;

const AVATAR_ACTIONS_MOTION_TRANSITION = {
  duration: 0.25,
  ease: "easeOut",
} as const;

const AVATAR_POSITION_MOTION_TRANSITION = {
  duration: 0.25,
  ease: "easeOut",
} as const;

function AvatarPreview({
  avatarSquishKey,
  avatarUrl,
  previewName,
}: {
  avatarSquishKey: number;
  avatarUrl: string;
  previewName: string;
}) {
  const emojiAvatar = parseEmojiAvatarDataUrl(avatarUrl);
  const hasAvatarUrl = avatarUrl.trim().length > 0;

  return (
    <div className="flex h-48 w-48 items-center justify-center">
      {emojiAvatar ? (
        <div
          aria-label={`${previewName} avatar`}
          className="relative flex h-full w-full shrink-0 items-center justify-center overflow-hidden rounded-full transition-colors duration-[250ms] ease-out"
          data-testid="onboarding-avatar-preview"
          role="img"
          style={{ backgroundColor: emojiAvatar.color }}
        >
          <span
            className={cn(
              "ambush-avatar-emoji-glyph flex h-full w-full items-center justify-center text-[6rem] leading-[6.25rem]",
              avatarSquishKey > 0 && "ambush-avatar-squish",
            )}
            data-testid="onboarding-avatar-preview-emoji"
            key={avatarSquishKey}
          >
            {emojiAvatar.emoji}
          </span>
        </div>
      ) : !hasAvatarUrl ? (
        <div
          aria-label="Add a display image"
          className="flex h-full w-full shrink-0 items-center justify-center rounded-full border-2 border-dashed border-border bg-background text-primary"
          data-testid="onboarding-avatar-preview"
          role="img"
        >
          <Plus className="h-14 w-14" aria-hidden="true" />
        </div>
      ) : (
        <ProfileAvatar
          avatarUrl={avatarUrl}
          className="h-full w-full rounded-full text-5xl"
          iconClassName="h-14 w-14"
          label={previewName}
          testId="onboarding-avatar-preview"
        />
      )}
    </div>
  );
}

function AvatarStepActions({
  canSubmit,
  hidden,
  isSaving,
  isUploadingAvatar,
  onBack,
  onContinueWithoutSaving,
  onSkipForNow,
  onSubmit,
  saveRecovery,
  showBack,
  showAlwaysSkip,
}: {
  canSubmit: boolean;
  hidden: boolean;
  isSaving: boolean;
  isUploadingAvatar: boolean;
  onBack: () => void;
  onContinueWithoutSaving: () => void;
  onSkipForNow: () => void;
  onSubmit: () => void;
  saveRecovery: ProfileStepState["saveRecovery"];
  showBack: boolean;
  showAlwaysSkip: boolean;
}) {
  const areNavigationActionsDisabled = isSaving || isUploadingAvatar;

  return (
    <OnboardingFooter>
      <AnimatePresence initial={false} mode="popLayout">
        {hidden ? null : (
          <motion.div
            className="flex w-full origin-center flex-col items-center gap-3"
            animate={{
              opacity: 1,
              scale: 1,
            }}
            exit={{
              opacity: 0,
              scale: 0.94,
            }}
            initial={{
              opacity: 0,
              scale: 0.94,
            }}
            transition={AVATAR_ACTIONS_MOTION_TRANSITION}
          >
            <Button
              className={ONBOARDING_PRIMARY_CTA_CLASS}
              data-testid="onboarding-next"
              disabled={!canSubmit}
              onClick={onSubmit}
              type="button"
            >
              {isSaving || isUploadingAvatar ? (
                <Spinner
                  aria-label={isSaving ? "Saving profile" : "Uploading avatar"}
                  className="h-4 w-4 border-2"
                />
              ) : (
                "Next"
              )}
            </Button>

            {saveRecovery.canSkipForNow ? (
              // Error-recovery path: exits onboarding entirely when there is no
              // saved display name to fall back on.
              <Button
                className="h-10 w-full text-muted-foreground hover:text-accent-foreground"
                data-testid="onboarding-skip"
                disabled={areNavigationActionsDisabled}
                onClick={onSkipForNow}
                type="button"
                variant="ghost"
              >
                Skip for now
              </Button>
            ) : showAlwaysSkip && !saveRecovery.errorMessage ? (
              // Normal path: advances to the theme step without saving an avatar.
              <Button
                className="h-10 w-full text-muted-foreground hover:text-accent-foreground"
                data-testid="onboarding-skip"
                disabled={areNavigationActionsDisabled}
                onClick={onContinueWithoutSaving}
                type="button"
                variant="ghost"
              >
                Skip for now
              </Button>
            ) : null}

            {saveRecovery.canAdvanceWithoutSaving ? (
              <Button
                className="h-10 w-full text-muted-foreground hover:text-accent-foreground"
                data-testid="onboarding-next-without-saving"
                disabled={areNavigationActionsDisabled}
                onClick={onContinueWithoutSaving}
                type="button"
                variant="ghost"
              >
                Continue without saving
              </Button>
            ) : null}

            {showBack ? (
              <Button
                className="h-10 w-full text-muted-foreground hover:text-accent-foreground"
                data-testid="onboarding-back"
                disabled={areNavigationActionsDisabled}
                onClick={onBack}
                type="button"
                variant="ghost"
              >
                Back
              </Button>
            ) : null}
          </motion.div>
        )}
      </AnimatePresence>
    </OnboardingFooter>
  );
}

export function AvatarStep({
  actions,
  direction,
  showAlwaysSkip = false,
  showBack = true,
  state,
}: AvatarStepProps) {
  const {
    advanceWithoutSaving,
    back,
    onUploadingChange,
    skipForNow,
    submit,
    updateAvatarUrl,
  } = actions;
  const { avatar, isSaving, isUploadingAvatar, name, saveRecovery } = state;
  const [avatarSquishKey, setAvatarSquishKey] = React.useState(0);
  const [avatarEditorMode, setAvatarEditorMode] =
    React.useState<AvatarMode>("image");
  const [isCustomColorPickerOpen, setIsCustomColorPickerOpen] =
    React.useState(false);
  const hasAvatarDraft = avatar.draftUrl.trim().length > 0;
  const canSubmit = hasAvatarDraft && !isSaving && !isUploadingAvatar;
  const areActionsHidden = isCustomColorPickerOpen;
  const previewName =
    name.draftValue.trim() || name.savedValue.trim() || "Your avatar";
  const animateEmojiAvatarChange = React.useCallback(() => {
    setAvatarSquishKey((key) => key + 1);
  }, []);

  return (
    <OnboardingSlideTransition
      // pb clears the always-docked footer: the emoji/color grid is the tallest
      // onboarding content and overflows on short windows, so the shell's own
      // bottom reserve isn't enough to scroll the last rows out from under the
      // fixed CTA group + scrim.
      className="flex w-full flex-col items-center pb-20"
      data-testid="onboarding-page-avatar"
      direction={direction}
      transitionKey={`avatar-${direction}`}
    >
      <motion.div
        className="grid w-full max-w-[1080px] items-start gap-12 lg:grid-cols-[minmax(300px,420px)_minmax(0,500px)] lg:gap-16"
        layout="position"
        layoutDependency={`${avatarEditorMode}-${isCustomColorPickerOpen}`}
        transition={AVATAR_POSITION_MOTION_TRANSITION}
      >
        <div className="flex w-full flex-col items-center text-center lg:items-start lg:text-left">
          <div className="w-full max-w-[500px]">
            <h1 className="text-title font-normal text-foreground">
              Next, add a display image
            </h1>
            <p className="mt-5 text-sm leading-6 text-muted-foreground">
              Choose an image or emoji as your avatar
            </p>
          </div>

          <div className="mt-12 grid justify-items-center gap-3 lg:justify-items-start">
            <div className="relative h-48 w-48">
              <AvatarPreview
                avatarSquishKey={avatarSquishKey}
                avatarUrl={avatar.draftUrl}
                previewName={previewName}
              />
            </div>
          </div>
        </div>

        <motion.div
          className="w-full"
          layout="position"
          layoutDependency={`${avatarEditorMode}-${isCustomColorPickerOpen}`}
          transition={AVATAR_POSITION_MOTION_TRANSITION}
        >
          <ProfileAvatarEditor
            avatarUrl={avatar.draftUrl}
            disabled={isSaving}
            emojiPickerTheme="auto"
            emojiPickerThemeVars={NEUTRAL_EMOJI_PICKER_THEME_VARS}
            onCustomColorPickerOpenChange={setIsCustomColorPickerOpen}
            onEmojiAvatarChange={animateEmojiAvatarChange}
            onModeChange={setAvatarEditorMode}
            onUploadingChange={onUploadingChange}
            onUrlChange={updateAvatarUrl}
            previewName={previewName}
            testIdPrefix="onboarding-avatar"
          />

          {saveRecovery.errorMessage ? (
            <ErrorBanner message={saveRecovery.errorMessage} />
          ) : null}

          <AvatarStepActions
            canSubmit={canSubmit}
            hidden={areActionsHidden}
            isSaving={isSaving}
            isUploadingAvatar={isUploadingAvatar}
            onBack={back}
            onContinueWithoutSaving={advanceWithoutSaving}
            onSkipForNow={skipForNow}
            onSubmit={submit}
            saveRecovery={saveRecovery}
            showBack={showBack}
            showAlwaysSkip={showAlwaysSkip}
          />
        </motion.div>
      </motion.div>
    </OnboardingSlideTransition>
  );
}
