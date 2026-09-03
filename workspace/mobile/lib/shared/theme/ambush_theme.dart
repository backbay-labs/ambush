import 'package:flutter/material.dart';

import 'accent_colors.dart';
import 'app_colors.dart';
import 'quiet.dart';

/// Name of the light half of the first-party pair. Ambush Day declares its own
/// Quiet surfaces, so its chrome is painted verbatim rather than derived.
const ambushThemeName = 'ambush-day';

/// Name of the dark half, and the app's default. Paired with [ambushThemeName]
/// in `themePairs`, so the two behave as a single "Ambush" choice under System
/// mode.
const ambushDarkThemeName = 'ambush-night';

/// Whether [themeName] is either half of the Ambush pair.
bool isAmbushTheme(String themeName) =>
    themeName == ambushThemeName || themeName == ambushDarkThemeName;

/// Whether the current widget tree is using the first-party Ambush treatment.
bool isAmbushThemeContext(BuildContext context) =>
    Theme.of(context).extension<AppColors>()?.topSectionGradient != null;

/// Primary foreground for the mobile top navigation.
Color navigationPrimaryForeground(BuildContext context) =>
    Theme.of(context).colorScheme.onSurface;

/// Secondary label and placeholder foreground for the mobile top navigation.
Color navigationSecondaryForeground(BuildContext context) =>
    Theme.of(context).colorScheme.onSurfaceVariant;

/// Channel-section label and icon foreground for the mobile side navigation.
///
/// Section labels need more hierarchy than a placeholder, so they sit one step
/// up the ink ramp from [navigationSecondaryForeground].
Color navigationSectionForeground(BuildContext context) =>
    Theme.of(context).extension<AppColors>()?.inkMid ??
    Theme.of(context).colorScheme.onSurfaceVariant;

/// Search-field surface for the mobile top navigation.
Color navigationSearchSurface(BuildContext context) =>
    Theme.of(context).colorScheme.surfaceContainerHighest;

/// A navigation divider: the hairline that separates without asserting.
Color navigationDivider(BuildContext context, double opacity) =>
    Theme.of(context).colorScheme.outline.withValues(alpha: opacity);

/// Ambush renders with its fixed neutral foreground while preserving the stored
/// wire accent so the user's choice returns on another theme.
int effectiveAccentIndex(String themeName, String storedAccent) {
  if (isAmbushTheme(themeName)) return neutralAccentIndex;
  return accentIndexForWireValue(storedAccent) ?? defaultAccentIndex;
}

/// The instrument surface behind the app's top section, or null when
/// [themeName] is not an Ambush theme — in which case the section keeps its
/// default frosted fill.
///
/// Both stops are the same chrome, so the section paints as one flat field:
/// separation is carried by a hairline and a step in lightness, never by a
/// gradient. [brightness] comes from the applied color scheme rather than the
/// theme name, so System mode picks the right surface as the OS switches.
LinearGradient? ambushTopSectionGradient(
  String themeName,
  Brightness brightness,
) {
  if (!isAmbushTheme(themeName)) return null;

  final steel = brightness == Brightness.dark
      ? quietNight.steel
      : quietDay.steel;
  return LinearGradient(
    begin: Alignment.topCenter,
    end: Alignment.bottomCenter,
    colors: [steel, steel],
  );
}
