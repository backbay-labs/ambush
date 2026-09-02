import 'package:flutter/material.dart';

import 'accent_colors.dart';
import 'quiet.dart';

/// Ambush Day — the fallback light scheme when no catalog theme resolves.
final lightColorScheme = quietColorScheme(quietDay);

/// Ambush Night — the fallback dark scheme when no catalog theme resolves.
final darkColorScheme = quietColorScheme(quietNight);

/// Compute a contrast-safe foreground color for a given background.
/// Uses WCAG contrast ratio (higher ratio wins) instead of a simple luminance
/// cutoff, so colors like Blue (#3B82F6) correctly get black text (5.7:1)
/// rather than white (3.7:1).
Color contrastForeground(Color bg) {
  final lum = bg.computeLuminance();
  // WCAG contrast ratio: (L1 + 0.05) / (L2 + 0.05), L1 >= L2
  final contrastWithBlack = (lum + 0.05) / 0.05; // black luminance = 0
  final contrastWithWhite = 1.05 / (lum + 0.05); // white luminance = 1
  return contrastWithBlack >= contrastWithWhite
      ? const Color(0xFF000000)
      : const Color(0xFFFFFFFF);
}

/// Returns a [ColorScheme] with the given accent applied as primary.
ColorScheme applyAccent(ColorScheme base, int accentIndex) {
  if (accentIndex < 0 || accentIndex >= accentColors.length) {
    return base;
  }
  final color = accentColorForScheme(base, accentIndex);
  final onColor = contrastForeground(color);

  return base.copyWith(primary: color, onPrimary: onColor, surfaceTint: color);
}
