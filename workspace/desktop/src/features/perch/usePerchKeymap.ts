import * as React from "react";

import { hasPrimaryShortcutModifier } from "@/shared/lib/platform";

import {
  PERCH_BINDINGS,
  type PerchBinding,
  type PerchRowType,
  type PerchVerdictVerb,
} from "./lib/perchKeymapRegistry";

/**
 * The row keymap, driven from `PERCH_BINDINGS`.
 *
 * ONE bubble-phase listener on `window`, matching the house rule in
 * `useAppShellKeyboardShortcuts`: bail on `event.repeat` (a held key is one
 * intention, not forty), on `defaultPrevented` (a nested control already
 * answered), on a primary modifier (that is a global chord, not a row verb),
 * and on an editable target (an operator typing a rationale is not pressing R).
 *
 * `Escape` is deliberately NOT in `PERCH_BINDINGS` and this hook never handles
 * it. The Verdict Row acquires an escape surface instead, which is what stops
 * the app-level mark-as-read shortcut from taking the key; a second Escape
 * handler here would race it.
 *
 * THE GRANT IS NOT DISPATCHED HERE even though `G` is in the registry. Its two
 * strokes are inseparable from the dwell that gates the second one, and only
 * the control watching the blast radius can know whether that gate is open, so
 * `GrantControl` owns both. The registry is the ratified KEYMAP; it does not
 * dictate which module listens. A caller wires `onVerb` to ignore `grant` for
 * that reason, and the JSDoc on `onVerb` says so at the call site.
 */
export type PerchKeymapHandlers = {
  /** The selected row's type, or null when nothing is selected. */
  rowType: PerchRowType | null;
  /**
   * A verdict verb was pressed. `grant` arrives here too, and a caller that
   * renders `GrantControl` must ignore it: the control dispatches its own.
   */
  onVerb?: (verb: PerchVerdictVerb) => void;
  onMove?: (delta: 1 | -1) => void;
  onOpen?: () => void;
  onPromote?: () => void;
  onSnooze?: () => void;
  onMarkDone?: () => void;
  onMarkUnread?: () => void;
};

function normalizeKey(key: string): string {
  return key.length === 1 ? key.toLowerCase() : key.toLowerCase();
}

/** Whether the event landed in something the operator is typing into. */
function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

/** The binding for `key` that is OFFERED on `rowType`, if any. */
function bindingFor(
  key: string,
  rowType: PerchRowType,
): PerchBinding | undefined {
  return PERCH_BINDINGS.find(
    (binding) =>
      normalizeKey(binding.key) === key && binding.rowTypes.includes(rowType),
  );
}

/** What a keypress resolves to. `null` means this hook does not handle it. */
export type PerchKeyAction =
  | { kind: "verb"; verb: PerchVerdictVerb }
  | { kind: "move"; delta: 1 | -1 }
  | { kind: "open" }
  | { kind: "promote" }
  | { kind: "snooze" }
  | { kind: "mark-done" }
  | { kind: "mark-unread" };

/** The parts of a `KeyboardEvent` the resolver reads. */
export type PerchKeyInput = {
  key: string;
  repeat?: boolean;
  defaultPrevented?: boolean;
  primaryModifier?: boolean;
  altKey?: boolean;
  editableTarget?: boolean;
};

/**
 * The whole dispatch decision, as a pure function.
 *
 * Separated from the listener so the four guards and the registry lookup can
 * be checked as a table rather than through a DOM: the guards are the part
 * that matters (a held key must be one intention, a rationale being typed must
 * not be a verdict) and they are exactly the part a happy-path DOM test would
 * never reach.
 */
export function resolvePerchKey(
  input: PerchKeyInput,
  rowType: PerchRowType | null,
): PerchKeyAction | null {
  if (
    input.repeat ||
    input.defaultPrevented ||
    input.primaryModifier ||
    input.altKey ||
    input.editableTarget
  ) {
    return null;
  }
  if (rowType === null) return null;
  const key = normalizeKey(input.key);
  const binding = bindingFor(key, rowType);
  if (!binding) return null;
  if (binding.verb) return { kind: "verb", verb: binding.verb };
  switch (key) {
    case "j":
      return { kind: "move", delta: 1 };
    case "k":
      return { kind: "move", delta: -1 };
    case "e":
      return { kind: "promote" };
    case "s":
      return { kind: "snooze" };
    case "m":
      return { kind: "mark-done" };
    case "u":
      return { kind: "mark-unread" };
    case "enter":
      return { kind: "open" };
    default:
      return null;
  }
}

/**
 * Whether `key` is declared DISABLED on `rowType` rather than simply absent.
 *
 * INV-34: a control that is absent teaches nothing, and a key that silently
 * does nothing is worse — the operator cannot tell a broken build from a rule.
 * A disabled binding is a no-op here and a stated reason in the UI.
 */
export function isDisabledOnRow(key: string, rowType: PerchRowType): boolean {
  const normalized = normalizeKey(key);
  return PERCH_BINDINGS.some(
    (binding) =>
      normalizeKey(binding.key) === normalized &&
      (binding.disabledOn ?? []).includes(rowType),
  );
}

export function usePerchKeymap(handlers: PerchKeymapHandlers): void {
  const handlersRef = React.useRef(handlers);
  handlersRef.current = handlers;

  React.useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      const current = handlersRef.current;
      const action = resolvePerchKey(
        {
          key: event.key,
          repeat: event.repeat,
          defaultPrevented: event.defaultPrevented,
          primaryModifier: hasPrimaryShortcutModifier(event),
          altKey: event.altKey,
          editableTarget: isEditableTarget(event.target),
        },
        current.rowType,
      );
      if (!action) return;
      switch (action.kind) {
        case "verb":
          current.onVerb?.(action.verb);
          break;
        case "move":
          current.onMove?.(action.delta);
          break;
        case "open":
          current.onOpen?.();
          break;
        case "promote":
          current.onPromote?.();
          break;
        case "snooze":
          current.onSnooze?.();
          break;
        case "mark-done":
          current.onMarkDone?.();
          break;
        case "mark-unread":
          current.onMarkUnread?.();
          break;
      }
      event.preventDefault();
    }

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);
}
