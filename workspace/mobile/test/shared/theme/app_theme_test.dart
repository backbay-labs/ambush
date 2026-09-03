import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ambush/shared/theme/app_colors.dart';
import 'package:ambush/shared/theme/app_theme.dart';

void main() {
  test('disables Material touch ripples in every app theme', () {
    expect(AppTheme.light().splashFactory, NoSplash.splashFactory);
    expect(AppTheme.dark().splashFactory, NoSplash.splashFactory);
  });

  test('uses Plex and separates the popover with a hairline', () {
    final theme = AppTheme.light();
    final popupTheme = theme.popupMenuTheme;
    final shape = popupTheme.shape! as RoundedRectangleBorder;
    final side = shape.side;

    expect(popupTheme.textStyle?.fontFamily, 'IBM Plex Sans');
    expect(popupTheme.color, theme.colorScheme.surfaceContainerHigh);
    expect(popupTheme.elevation, 0);
    expect(shape.borderRadius, BorderRadius.circular(Radii.popover));
    expect(side.color, theme.colorScheme.outline);
    expect(side.width, 1);
  });

  test('keeps inactive Huddle controls distinct in dark mode', () {
    final colors = AppTheme.dark().extension<AppColors>()!;

    expect(colors.huddleControlSurface, isNot(colors.huddleDrawerSurface));
    // Elevation is a step in lightness. At the bottom of the range relative
    // luminance barely moves, so measure the step as a contrast ratio.
    final control = colors.huddleControlSurface.computeLuminance() + 0.05;
    final drawer = colors.huddleDrawerSurface.computeLuminance() + 0.05;
    expect(control / drawer, greaterThan(1.05));
  });
}
