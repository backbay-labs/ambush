import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'app_colors.dart';
import 'color_scheme.dart';
import 'grid.dart';
import 'quiet.dart';
import 'text_theme.dart';

/// One machined chamfer, everywhere. Every surface in the product takes the
/// same 2px corner: not square, which is the broadsheet look, and not rounded,
/// which softens an instrument. Matches desktop, where the whole Tailwind
/// radius scale resolves to `var(--radius)`.
class Radii {
  static const double chamfer = 2.0;

  static const double xs = chamfer;
  static const double sm = chamfer;
  static const double md = chamfer;
  static const double lg = chamfer;

  /// Grouped rows, fields, and utility containers.
  static const double container = chamfer;
  static const double card = chamfer;
  static const double popover = chamfer;
  static const double dialog = chamfer;

  /// Fully rounds pills, circles, and other capsule shapes.
  static const double full = 999.0;
}

class AppTheme {
  static ThemeData light({
    ColorScheme? colorScheme,
    QuietSurfaces? surfaces,
    Gradient? topSectionGradient,
  }) {
    final scheme = colorScheme ?? lightColorScheme;
    final appColors = _appColors(
      scheme,
      colorScheme == null ? quietDay : surfaces,
      topSectionGradient: topSectionGradient,
    );

    return _buildTheme(
      scheme: scheme,
      appColors: appColors,
      brightness: Brightness.light,
      statusBarIconBrightness: Brightness.dark,
      statusBarBrightness: Brightness.light,
    );
  }

  static ThemeData dark({
    ColorScheme? colorScheme,
    QuietSurfaces? surfaces,
    Gradient? topSectionGradient,
  }) {
    final scheme = colorScheme ?? darkColorScheme;
    final appColors = _appColors(
      scheme,
      colorScheme == null ? quietNight : surfaces,
      topSectionGradient: topSectionGradient,
    );

    return _buildTheme(
      scheme: scheme,
      appColors: appColors,
      brightness: Brightness.dark,
      statusBarIconBrightness: Brightness.light,
      statusBarBrightness: Brightness.dark,
    );
  }

  /// The roles the color scheme has no name for.
  ///
  /// A theme that declares [surfaces] hands them over verbatim. A borrowed
  /// syntax theme has no index and no plate, so those roles are filled from
  /// the scheme it derived: consequence borrows its error color, and the
  /// raised band and graduation sit between the surfaces it does have.
  static AppColors _appColors(
    ColorScheme scheme,
    QuietSurfaces? surfaces, {
    Gradient? topSectionGradient,
  }) {
    return AppColors(
      index: surfaces?.index ?? scheme.error,
      grad: surfaces?.grad ?? scheme.outline,
      plateHigh: surfaces?.plateHigh ?? scheme.surfaceContainerHigh,
      inkMid:
          surfaces?.inkMid ??
          Color.lerp(scheme.onSurfaceVariant, scheme.onSurface, 0.5)!,
      huddleDrawerSurface: scheme.surface,
      huddleControlSurface: scheme.surfaceContainerHighest,
      onHuddleDrawer: scheme.onSurface,
      topSectionGradient: topSectionGradient,
    );
  }

  static ThemeData _buildTheme({
    required ColorScheme scheme,
    required AppColors appColors,
    required Brightness brightness,
    required Brightness statusBarIconBrightness,
    required Brightness statusBarBrightness,
  }) {
    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      splashFactory: NoSplash.splashFactory,
      scaffoldBackgroundColor: scheme.surface,
      extensions: [appColors],
      fontFamily: 'IBM Plex Sans',
      fontFamilyFallback: const ['Helvetica Neue', 'Helvetica', 'Arial'],
      textTheme: textTheme,
      appBarTheme: AppBarTheme(
        backgroundColor: Colors.transparent,
        foregroundColor: scheme.onSurface,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        scrolledUnderElevation: 0,
        titleTextStyle: textTheme.titleMedium?.copyWith(
          color: scheme.onSurface,
        ),
        systemOverlayStyle: SystemUiOverlayStyle(
          statusBarColor: Colors.transparent,
          statusBarIconBrightness: statusBarIconBrightness,
          statusBarBrightness: statusBarBrightness,
        ),
      ),

      // Bottom navigation: clean style, no indicator pill
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: scheme.surface,
        elevation: 0,
        indicatorColor: Colors.transparent,
        iconTheme: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return IconThemeData(color: scheme.primary, size: 24);
          }
          return IconThemeData(color: scheme.onSurfaceVariant, size: 24);
        }),
        labelTextStyle: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return textTheme.labelSmall?.copyWith(
              color: scheme.primary,
              fontWeight: FontWeight.w600,
            );
          }
          return textTheme.labelSmall?.copyWith(color: scheme.onSurfaceVariant);
        }),
      ),

      // Buttons: h-9 (36px), px-4 (16px)
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: scheme.primary,
          foregroundColor: scheme.onPrimary,
          elevation: 0,
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          minimumSize: const Size(0, 36),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(Radii.md),
          ),
          textStyle: textTheme.labelMedium?.copyWith(
            fontWeight: FontWeight.w500,
          ),
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          elevation: 0,
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          minimumSize: const Size(0, 36),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(Radii.md),
          ),
          textStyle: textTheme.labelMedium?.copyWith(
            fontWeight: FontWeight.w500,
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          backgroundColor: scheme.surface,
          foregroundColor: scheme.onSurface,
          side: BorderSide(color: scheme.outline, width: 1),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          minimumSize: const Size(0, 36),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(Radii.md),
          ),
          textStyle: textTheme.labelMedium?.copyWith(
            fontWeight: FontWeight.w500,
          ),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: scheme.onSurface,
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          minimumSize: const Size(0, 36),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(Radii.md),
          ),
          textStyle: textTheme.labelMedium?.copyWith(
            fontWeight: FontWeight.w500,
          ),
        ),
      ),

      // Cards are flat chrome: a lightness step and a hairline, no elevation.
      cardTheme: CardThemeData(
        color: scheme.surfaceContainerHighest,
        margin: EdgeInsets.zero,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(Radii.lg),
        ),
      ),

      // Inputs: outlined, h-9 (36px)
      inputDecorationTheme: InputDecorationTheme(
        filled: false,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(Radii.md),
          borderSide: BorderSide(color: scheme.outline),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(Radii.md),
          borderSide: BorderSide(color: scheme.outline),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(Radii.md),
          borderSide: BorderSide(color: scheme.primary),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(Radii.md),
          borderSide: BorderSide(color: scheme.error),
        ),
        focusedErrorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(Radii.md),
          borderSide: BorderSide(color: scheme.error),
        ),
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 12,
          vertical: 10,
        ),
        isDense: true,
      ),

      // Dialogs: hairline edge, no elevation
      dialogTheme: DialogThemeData(
        backgroundColor: scheme.surface,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(Radii.dialog),
          side: BorderSide(color: scheme.outline),
        ),
        titleTextStyle: textTheme.titleLarge?.copyWith(
          color: scheme.onSurface,
          fontSize: 18,
          fontWeight: FontWeight.w600,
          letterSpacing: -0.3,
        ),
        contentTextStyle: textTheme.bodyMedium?.copyWith(
          color: scheme.onSurfaceVariant,
        ),
      ),

      // A track's spent portion is a graduation, never information.
      progressIndicatorTheme: ProgressIndicatorThemeData(
        strokeWidth: 2,
        color: scheme.primary,
        circularTrackColor: appColors.grad,
      ),

      listTileTheme: ListTileThemeData(
        titleTextStyle: textTheme.titleSmall?.copyWith(color: scheme.onSurface),
        subtitleTextStyle: textTheme.bodyMedium?.copyWith(
          color: scheme.secondary,
        ),
        iconColor: scheme.secondary,
        contentPadding: const EdgeInsets.symmetric(horizontal: Grid.twelve),
        minVerticalPadding: Grid.twelve,
        horizontalTitleGap: Grid.twelve,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(Radii.md),
        ),
      ),

      chipTheme: ChipThemeData(
        labelStyle: textTheme.bodySmall?.copyWith(color: scheme.secondary),
        // M3 resolves the chip container via `color` (WidgetStateProperty);
        // `selectedColor` is the legacy M2 path and is ignored here. Selected
        // filter chips (Pulse/Search/Activity tabs) use the accent.
        color: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) return scheme.primary;
          return scheme.surfaceContainerHighest;
        }),
        checkmarkColor: scheme.onPrimary,
        shape: RoundedRectangleBorder(
          side: BorderSide.none,
          borderRadius: BorderRadius.circular(Radii.sm),
        ),
        side: BorderSide.none,
        padding: const EdgeInsets.symmetric(horizontal: 8),
        labelPadding: EdgeInsets.zero,
      ),

      // Popups and menus sit on the lamplit plate, a step above the room.
      // Separation is the hairline, never a blur.
      popupMenuTheme: PopupMenuThemeData(
        color: scheme.surfaceContainerHigh,
        elevation: 0,
        surfaceTintColor: Colors.transparent,
        textStyle: textTheme.labelLarge?.copyWith(color: scheme.onSurface),
        labelTextStyle: WidgetStatePropertyAll(
          textTheme.labelLarge?.copyWith(color: scheme.onSurface),
        ),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(Radii.popover),
          side: BorderSide(color: scheme.outline),
        ),
      ),

      // Bottom sheet: match the dialog chamfer
      bottomSheetTheme: BottomSheetThemeData(
        backgroundColor: scheme.surface,
        elevation: 0,
        shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(
            top: Radius.circular(Radii.dialog),
          ),
        ),
      ),

      // Tooltips: an ink fill with a room-colored label
      tooltipTheme: TooltipThemeData(
        decoration: BoxDecoration(
          color: scheme.primary,
          borderRadius: BorderRadius.circular(Radii.md),
        ),
        textStyle: textTheme.bodySmall?.copyWith(
          color: scheme.onPrimary,
          fontSize: 12,
        ),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      ),

      dividerTheme: DividerThemeData(
        color: scheme.outline,
        thickness: 1,
        space: 1,
      ),

      // Snackbar
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(Radii.md),
        ),
      ),
    );
  }
}
