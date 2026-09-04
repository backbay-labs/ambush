import * as React from "react";

import { cn } from "@/shared/lib/cn";
import { performDefaultHaptic } from "@/shared/lib/haptics";

const SLIDER_TICK_STEP = 10;

function percentFromSliderValue(
  value: number,
  min: number,
  max: number,
): number {
  if (max === min) {
    return 0;
  }
  return ((value - min) / (max - min)) * 100;
}

function buildAnchoredSliderTicks(
  min: number,
  max: number,
  resetValue: number,
): number[] {
  const ticks = new Set<number>();
  for (let tick = resetValue; tick >= min; tick -= SLIDER_TICK_STEP) {
    ticks.add(Math.round(tick));
  }
  for (
    let tick = resetValue + SLIDER_TICK_STEP;
    tick <= max;
    tick += SLIDER_TICK_STEP
  ) {
    ticks.add(Math.round(tick));
  }
  return [...ticks].sort((first, second) => first - second);
}

function findCrossedSliderTick(
  previousValue: number,
  nextValue: number,
  ticks: number[],
): number | null {
  if (previousValue === nextValue) {
    return null;
  }

  if (nextValue > previousValue) {
    return (
      ticks.find((tick) => tick > previousValue && tick <= nextValue) ?? null
    );
  }

  return (
    [...ticks]
      .reverse()
      .find((tick) => tick < previousValue && tick >= nextValue) ?? null
  );
}

type AvatarFramingSliderProps = {
  ariaDescribedBy?: string;
  ariaLabel?: string;
  ariaValueText?: string;
  compact?: boolean;
  disabled?: boolean;
  handleAlwaysVisible?: boolean;
  helpText?: string | null;
  helpTestId?: string;
  max: number;
  min: number;
  onChange: (value: number) => void;
  onReset: () => void;
  resetValue: number;
  resetLabel?: string;
  resetTestId: string;
  testId: string;
  tipText?: string | null;
  value: number;
};

export function AvatarFramingSlider({
  ariaDescribedBy,
  ariaLabel = "Avatar size",
  ariaValueText,
  compact = false,
  disabled = false,
  handleAlwaysVisible = false,
  helpText = null,
  helpTestId,
  max,
  min,
  onChange,
  onReset,
  resetValue,
  resetLabel = "Reset avatar size",
  resetTestId,
  testId,
  tipText = null,
  value,
}: AvatarFramingSliderProps) {
  const sliderRef = React.useRef<HTMLDivElement | null>(null);
  const activePointerRef = React.useRef<number | null>(null);
  const valueRef = React.useRef(value);
  const lastHapticTickRef = React.useRef<number | null>(null);
  const [isHovered, setIsHovered] = React.useState(false);
  const [isFocused, setIsFocused] = React.useState(false);
  const [isInteracting, setIsInteracting] = React.useState(false);
  const fill = percentFromSliderValue(value, min, max);
  const isActive = isHovered || isFocused || isInteracting;
  const tipId = React.useId();
  const ticks = React.useMemo(
    () => buildAnchoredSliderTicks(min, max, resetValue),
    [max, min, resetValue],
  );

  React.useEffect(() => {
    valueRef.current = value;
  }, [value]);

  const commitValue = React.useCallback(
    (nextValue: number) => {
      const clampedValue = Math.min(max, Math.max(min, Math.round(nextValue)));
      const crossedTick = findCrossedSliderTick(
        valueRef.current,
        clampedValue,
        ticks,
      );
      valueRef.current = clampedValue;
      onChange(clampedValue);
      if (crossedTick !== null && crossedTick !== lastHapticTickRef.current) {
        lastHapticTickRef.current = crossedTick;
        performDefaultHaptic();
      } else if (crossedTick === null) {
        lastHapticTickRef.current = null;
      }
    },
    [max, min, onChange, ticks],
  );

  const commitPointerValue = React.useCallback(
    (clientX: number) => {
      const slider = sliderRef.current;
      if (!slider) {
        return;
      }
      const rect = slider.getBoundingClientRect();
      const progress = Math.min(
        1,
        Math.max(0, (clientX - rect.left) / Math.max(rect.width, 1)),
      );
      commitValue(min + progress * (max - min));
    },
    [commitValue, max, min],
  );

  const nudgeValue = React.useCallback(
    (delta: number) => {
      commitValue(value + delta);
    },
    [commitValue, value],
  );

  const resetTickStyle = {
    left: `${percentFromSliderValue(resetValue, min, max)}%`,
  };
  const sliderControl = (
    <div className="ambush-avatar-framing-slider-wrapper">
      <div
        aria-label={ariaLabel}
        aria-describedby={tipText ? tipId : ariaDescribedBy}
        aria-valuemax={max}
        aria-valuemin={min}
        aria-valuenow={value}
        aria-valuetext={ariaValueText}
        className={cn(
          "ambush-avatar-framing-slider",
          compact && "ambush-avatar-framing-slider--compact",
        )}
        data-active={isActive ? "true" : undefined}
        data-handle-visible={handleAlwaysVisible ? "true" : undefined}
        data-testid={testId}
        onKeyDown={(event) => {
          if (disabled) {
            return;
          }
          const step = event.shiftKey ? 10 : 1;
          if (event.key === "ArrowLeft" || event.key === "ArrowDown") {
            event.preventDefault();
            nudgeValue(-step);
          } else if (event.key === "ArrowRight" || event.key === "ArrowUp") {
            event.preventDefault();
            nudgeValue(step);
          } else if (event.key === "Home") {
            event.preventDefault();
            commitValue(min);
          } else if (event.key === "End") {
            event.preventDefault();
            commitValue(max);
          }
        }}
        onBlur={() => setIsFocused(false)}
        onFocus={() => setIsFocused(true)}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        onPointerCancel={(event) => {
          if (activePointerRef.current === event.pointerId) {
            activePointerRef.current = null;
            setIsInteracting(false);
          }
        }}
        onPointerDown={(event) => {
          if (disabled) {
            return;
          }
          event.preventDefault();
          event.currentTarget.setPointerCapture(event.pointerId);
          activePointerRef.current = event.pointerId;
          setIsInteracting(true);
          commitPointerValue(event.clientX);
        }}
        onPointerMove={(event) => {
          if (activePointerRef.current !== event.pointerId) {
            return;
          }
          commitPointerValue(event.clientX);
        }}
        onPointerUp={(event) => {
          if (activePointerRef.current === event.pointerId) {
            activePointerRef.current = null;
            setIsInteracting(false);
          }
        }}
        ref={sliderRef}
        role="slider"
        style={
          {
            "--ambush-avatar-framing-slider-fill": `${fill}%`,
          } as React.CSSProperties
        }
        tabIndex={disabled ? -1 : 0}
      >
        <div className="ambush-avatar-framing-slider-hashmarks">
          {ticks.map((tick) => (
            <span
              aria-hidden="true"
              className="ambush-avatar-framing-slider-hashmark"
              key={tick}
              style={{
                left: `${percentFromSliderValue(tick, min, max)}%`,
              }}
            />
          ))}
        </div>
        <div aria-hidden="true" className="ambush-avatar-framing-slider-fill" />
        <div
          aria-hidden="true"
          className="ambush-avatar-framing-slider-handle"
        />
      </div>
      <button
        aria-label={resetLabel}
        className="ambush-avatar-framing-slider-hashmark"
        data-reset="true"
        data-testid={resetTestId}
        disabled={disabled}
        onClick={(event) => {
          event.preventDefault();
          valueRef.current = resetValue;
          lastHapticTickRef.current = resetValue;
          performDefaultHaptic();
          onReset();
        }}
        style={resetTickStyle}
        title={resetLabel}
        type="button"
      />
      {tipText ? (
        <p
          className="ambush-avatar-framing-slider-tip"
          data-visible={isActive ? "true" : undefined}
          id={tipId}
        >
          {tipText}
        </p>
      ) : null}
    </div>
  );

  return helpText ? (
    <div className="grid gap-2">
      {sliderControl}
      <p
        className="px-1 text-center text-sm text-muted-foreground"
        data-testid={helpTestId}
      >
        {helpText}
      </p>
    </div>
  ) : (
    sliderControl
  );
}
