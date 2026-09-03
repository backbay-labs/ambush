import 'package:flutter/material.dart';

/// The Ambush palette.
///
/// The room is achromatic, the lamp is warm, and the one saturated value marks
/// an irreversible action that has not been decided yet. Ambush Night and
/// Ambush Day are the same material under two lighting conditions.
@immutable
class QuietSurfaces {
  /// The only chromatic value: an irreversible thing is here and undecided.
  /// Never text, never a fill, never a friendly control.
  final Color index;

  /// The room; the darkest surface anywhere.
  final Color night;

  /// Instrument chrome: bars, rails, wells, unselected rows.
  final Color steel;

  /// A hairline that separates without asserting.
  final Color rule;

  /// Graduations, ticks, and the spent part of a track — never information.
  final Color grad;

  /// The lamplit surface: the record, and the row being read.
  final Color plate;

  /// The raised band inside the plate: its head and its controls.
  final Color plateHigh;

  /// Engraved labels, provenance detail, numerals.
  final Color inkDim;

  /// Body, key/value, every machine-emitted string.
  final Color inkMid;

  /// The sentence the reader is asked to judge.
  final Color ink;

  const QuietSurfaces({
    required this.index,
    required this.night,
    required this.steel,
    required this.rule,
    required this.grad,
    required this.plate,
    required this.plateHigh,
    required this.inkDim,
    required this.inkMid,
    required this.ink,
  });

  /// A dark palette is one whose ink is lighter than its room. The day room
  /// is a stone grey deliberately close to the luminance midpoint, so a
  /// threshold on the ground alone would read it wrong.
  bool get isDark => ink.computeLuminance() > night.computeLuminance();
}

const quietNight = QuietSurfaces(
  index: Color(0xFFE05E28),
  night: Color(0xFF171717),
  steel: Color(0xFF1F1F1F),
  rule: Color(0xFF3E3E3E),
  grad: Color(0xFF727272),
  plate: Color(0xFF33281E),
  plateHigh: Color(0xFF3D3025),
  inkDim: Color(0xFFA49B90),
  inkMid: Color(0xFFBAB2A8),
  ink: Color(0xFFC9C1B7),
);

const quietDay = QuietSurfaces(
  index: Color(0xFF943106),
  night: Color(0xFFBCB5AD),
  steel: Color(0xFFC7C0B8),
  rule: Color(0xFF9C9893),
  grad: Color(0xFF7A7672),
  plate: Color(0xFFECCFB9),
  plateHigh: Color(0xFFF4D7C4),
  inkDim: Color(0xFF51443A),
  inkMid: Color(0xFF3E332A),
  ink: Color(0xFF292019),
);

/// Syntax inks: one lightness, low chroma, warm against cool. Structure reads
/// cool, literal content reads warm, anything that names something reads as
/// plain ink — so code survives with the hue stripped out.
@immutable
class QuietCodeInks {
  final Color warm;
  final Color cool;

  const QuietCodeInks({required this.warm, required this.cool});
}

const quietNightInks = QuietCodeInks(
  warm: Color(0xFFC4AFA2),
  cool: Color(0xFFA1B6C6),
);

const quietDayInks = QuietCodeInks(
  warm: Color(0xFF453126),
  cool: Color(0xFF1F3847),
);

/// A [ColorScheme] laid straight onto a declared surface palette.
///
/// The room is [QuietSurfaces.night], the chrome above it [QuietSurfaces.steel],
/// and the lamplit plate carries whatever the reader is judging. Consequence
/// travels on the index rule at a control's edge rather than on a hue, so
/// `error` is ink like every other emphatic mark.
ColorScheme quietColorScheme(QuietSurfaces s) {
  return ColorScheme(
    brightness: s.isDark ? Brightness.dark : Brightness.light,

    primary: s.ink,
    onPrimary: s.night,
    primaryContainer: s.plate,
    onPrimaryContainer: s.ink,

    secondary: s.inkDim,
    onSecondary: s.night,
    secondaryContainer: s.steel,
    onSecondaryContainer: s.inkMid,

    tertiary: s.ink,
    onTertiary: s.night,
    tertiaryContainer: s.plate,
    onTertiaryContainer: s.ink,

    error: s.ink,
    onError: s.night,
    errorContainer: s.plate,
    onErrorContainer: s.ink,

    surface: s.night,
    onSurface: s.ink,
    onSurfaceVariant: s.inkDim,

    outline: s.rule,
    outlineVariant: s.steel,

    inverseSurface: s.ink,
    onInverseSurface: s.night,
    inversePrimary: s.inkDim,

    shadow: const Color(0xFF000000),
    scrim: const Color(0xFF000000),
    surfaceTint: s.ink,

    surfaceContainerLowest: s.steel,
    surfaceContainerLow: s.steel,
    surfaceContainer: s.night,
    surfaceContainerHigh: s.plate,
    surfaceContainerHighest: s.steel,
  );
}
