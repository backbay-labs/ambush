import 'package:flutter/material.dart';

/// Roles the Material [ColorScheme] has no name for.
///
/// [index] is the one chromatic value in the product: it marks an irreversible
/// action that is here and undecided, and it leaves the moment the decision is
/// made. Everything else on this extension is a step on the achromatic room /
/// lamplit plate / ink ladder that the color scheme does not expose.
@immutable
class AppColors extends ThemeExtension<AppColors> {
  /// An irreversible action, held and undecided. Never text, never a fill.
  final Color index;

  /// Graduations, ticks, and the spent part of a track — never information.
  final Color grad;

  /// The raised band inside the lamplit plate: mention chips, match highlights.
  final Color plateHigh;

  /// Body, key/value, every machine-emitted string — one step above the
  /// engraved-label ink the scheme carries as `onSurfaceVariant`.
  final Color inkMid;

  final Color huddleDrawerSurface;
  final Color huddleControlSurface;
  final Color onHuddleDrawer;

  /// Fill for the app's top section, non-null only under the Ambush themes.
  /// Carried on the theme rather than read from a provider so any surface can
  /// opt in via `context.appColors.topSectionGradient` — see
  /// `ambushTopSectionGradient`.
  final Gradient? topSectionGradient;

  const AppColors({
    required this.index,
    required this.grad,
    required this.plateHigh,
    required this.inkMid,
    required this.huddleDrawerSurface,
    required this.huddleControlSurface,
    required this.onHuddleDrawer,
    this.topSectionGradient,
  });

  @override
  AppColors copyWith({
    Color? index,
    Color? grad,
    Color? plateHigh,
    Color? inkMid,
    Color? huddleDrawerSurface,
    Color? huddleControlSurface,
    Color? onHuddleDrawer,
    Gradient? topSectionGradient,
  }) => AppColors(
    index: index ?? this.index,
    grad: grad ?? this.grad,
    plateHigh: plateHigh ?? this.plateHigh,
    inkMid: inkMid ?? this.inkMid,
    huddleDrawerSurface: huddleDrawerSurface ?? this.huddleDrawerSurface,
    huddleControlSurface: huddleControlSurface ?? this.huddleControlSurface,
    onHuddleDrawer: onHuddleDrawer ?? this.onHuddleDrawer,
    topSectionGradient: topSectionGradient ?? this.topSectionGradient,
  );

  @override
  AppColors lerp(ThemeExtension<AppColors>? other, double t) {
    if (other is! AppColors) return this;
    return AppColors(
      index: Color.lerp(index, other.index, t)!,
      grad: Color.lerp(grad, other.grad, t)!,
      plateHigh: Color.lerp(plateHigh, other.plateHigh, t)!,
      inkMid: Color.lerp(inkMid, other.inkMid, t)!,
      huddleDrawerSurface: Color.lerp(
        huddleDrawerSurface,
        other.huddleDrawerSurface,
        t,
      )!,
      huddleControlSurface: Color.lerp(
        huddleControlSurface,
        other.huddleControlSurface,
        t,
      )!,
      onHuddleDrawer: Color.lerp(onHuddleDrawer, other.onHuddleDrawer, t)!,
      topSectionGradient: Gradient.lerp(
        topSectionGradient,
        other.topSectionGradient,
        t,
      ),
    );
  }
}
