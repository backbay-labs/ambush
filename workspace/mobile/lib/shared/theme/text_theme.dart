import 'package:flutter/material.dart';

const _fontFamily = 'IBM Plex Sans';
const _chatLineHeight = 22 / 16;

/// Interface text is set with tabular numerals so a figure that changes does
/// not shift the glyphs beside it. Human prose opts back out — see
/// [proportionalFigures] in `message_typography.dart`.
const tabularFigures = [FontFeature.tabularFigures()];

/// Optional 12sp body style for compact secondary metadata.
const bodyExtraSmallTextStyle = TextStyle(
  fontFamily: _fontFamily,
  fontSize: 12,
  fontWeight: FontWeight.w400,
  height: 1.25,
  letterSpacing: 0,
  fontFeatures: tabularFigures,
);

const textTheme = TextTheme(
  displayLarge: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 52,
    fontWeight: FontWeight.w400,
    height: 1.23,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  displayMedium: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 44,
    fontWeight: FontWeight.w400,
    height: 1.18,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  displaySmall: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 36,
    fontWeight: FontWeight.w400,
    height: 1.22,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  headlineLarge: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 32,
    fontWeight: FontWeight.w600,
    height: 1.25,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  headlineMedium: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 28,
    fontWeight: FontWeight.w600,
    height: 1.29,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  headlineSmall: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 24,
    fontWeight: FontWeight.w600,
    height: 1.33,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  titleLarge: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 24,
    fontWeight: FontWeight.w400,
    height: 1.25,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  titleMedium: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 20,
    fontWeight: FontWeight.w500,
    height: 1.3,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  titleSmall: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 16,
    fontWeight: FontWeight.w500,
    height: _chatLineHeight,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  labelLarge: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 16,
    fontWeight: FontWeight.w500,
    height: 1.2,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  labelMedium: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 14,
    fontWeight: FontWeight.w500,
    height: 1.25,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  labelSmall: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 11,
    fontWeight: FontWeight.w500,
    height: 1.2,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  bodyLarge: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 16,
    fontWeight: FontWeight.w400,
    height: 20 / 16,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  bodyMedium: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 14,
    fontWeight: FontWeight.w400,
    height: 1.3,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
  bodySmall: TextStyle(
    fontFamily: _fontFamily,
    fontSize: 14,
    fontWeight: FontWeight.w400,
    height: 1.25,
    letterSpacing: 0,
    fontFeatures: tabularFigures,
  ),
);
