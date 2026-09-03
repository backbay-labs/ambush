import 'package:flutter/material.dart';

import 'theme_extensions.dart';

/// The three ways a state is marked, none of them a hue.
///
/// [filled] says the thing is on, [hollow] says it is known but not on, and
/// [spent] says it is off — a graduation rather than information. The word
/// beside the mark always says which, so the encoding is redundant, not clever.
enum StatusMark { filled, hollow, spent }

/// The mark for a presence string, defaulting to offline for anything else.
StatusMark presenceMark(String presence) => switch (presence) {
  'online' => StatusMark.filled,
  'away' => StatusMark.hollow,
  _ => StatusMark.spent,
};

/// A circular dot drawn for [mark]: ink filled, ink hollow, or a spent ring.
///
/// A dot that overlaps artwork passes [separator], the surface it is cut out
/// of: the filled mark then carries that ring, and the hollow marks fill with
/// it so their own ring reads at badge sizes.
BoxDecoration statusMarkDecoration(
  BuildContext context,
  StatusMark mark, {
  double ringWidth = 1.5,
  Color? separator,
}) {
  final ink = context.colors.onSurface;
  final grad = context.appColors.grad;
  return switch (mark) {
    StatusMark.filled => BoxDecoration(
      color: ink,
      border: separator == null
          ? null
          : Border.all(color: separator, width: ringWidth),
      shape: BoxShape.circle,
    ),
    StatusMark.hollow => BoxDecoration(
      color: separator,
      border: Border.all(color: ink, width: ringWidth),
      shape: BoxShape.circle,
    ),
    StatusMark.spent => BoxDecoration(
      color: separator,
      border: Border.all(color: grad, width: ringWidth),
      shape: BoxShape.circle,
    ),
  };
}

/// The ink for a label or glyph sitting beside a [mark].
Color statusMarkInk(BuildContext context, StatusMark mark) =>
    mark == StatusMark.spent
    ? context.colors.onSurfaceVariant
    : context.colors.onSurface;
