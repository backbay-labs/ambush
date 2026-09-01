import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ambush/shared/theme/theme.dart';
import 'package:ambush/shared/widgets/frosted_app_bar.dart';

void main() {
  group('Ambush theme catalog entries', () {
    test('both halves are in the catalog', () {
      expect(findTheme(ambushThemeName), isNotNull);
      expect(findTheme(ambushDarkThemeName), isNotNull);
    });

    test('borrow the GitHub palettes', () {
      final ambush = findTheme(ambushThemeName)!;
      final github = findTheme('github-light')!;
      expect(ambush.bg, github.bg);
      expect(ambush.fg, github.fg);
      expect(ambush.comment, github.comment);

      final ambushDark = findTheme(ambushDarkThemeName)!;
      final githubDark = findTheme('github-dark')!;
      expect(ambushDark.bg, githubDark.bg);
      expect(ambushDark.fg, githubDark.fg);
      expect(ambushDark.comment, githubDark.comment);
    });

    test('are a light/dark pair', () {
      expect(findTheme(ambushThemeName)!.isDark, isFalse);
      expect(findTheme(ambushDarkThemeName)!.isDark, isTrue);
      expect(themePairFor(ambushThemeName), ambushDarkThemeName);
      expect(themePairFor(ambushDarkThemeName), ambushThemeName);
    });

    test('appear as a single System-mode option labelled "Ambush"', () {
      final paired = themeGroups().paired.map((t) => t.name);
      expect(paired, contains(ambushThemeName));
      expect(paired, isNot(contains(ambushDarkThemeName)));
      expect(pairedThemeLabel(ambushThemeName), 'Ambush');
      expect(themeSelectionLabel(ambushThemeName, ThemeMode.system), 'Ambush');
      expect(
        themeSelectionLabel(ambushDarkThemeName, ThemeMode.system),
        'Ambush',
      );
    });

    test('forces neutral rendering without changing the stored accent', () {
      const storedAccent = '#ef4444';

      expect(
        effectiveAccentIndex(ambushThemeName, storedAccent),
        neutralAccentIndex,
      );
      expect(
        effectiveAccentIndex(ambushDarkThemeName, storedAccent),
        neutralAccentIndex,
      );
      expect(
        effectiveAccentIndex('github-light', storedAccent),
        accentIndexForWireValue(storedAccent),
      );
      expect(storedAccent, '#ef4444');
    });

    test('resolve across brightnesses like any other pair', () {
      final resolved = resolveSchemes(ambushThemeName, ThemeMode.system);
      expect(resolved.forcedMode, isNull);
      expect(resolved.light.brightness, Brightness.light);
      expect(resolved.dark.brightness, Brightness.dark);
      expect(resolved.lightTheme?.name, ambushThemeName);
      expect(resolved.darkTheme?.name, ambushDarkThemeName);

      expect(
        effectiveTheme(ambushThemeName, ThemeMode.dark)?.name,
        ambushDarkThemeName,
      );
      expect(
        effectiveTheme(ambushDarkThemeName, ThemeMode.light)?.name,
        ambushThemeName,
      );
    });

    test(
      'fallbacks expose the effective Ambush theme for gradient selection',
      () {
        final coerced = resolveSchemes('nord', ThemeMode.light);
        expect(coerced.lightTheme?.name, ambushThemeName);
        expect(
          ambushTopSectionGradient(
            coerced.lightTheme!.name,
            coerced.light.brightness,
          ),
          isNotNull,
        );

        final unknown = resolveSchemes('not-a-theme', ThemeMode.light);
        expect(unknown.lightTheme?.name, ambushThemeName);
        expect(
          ambushTopSectionGradient(
            unknown.lightTheme!.name,
            unknown.light.brightness,
          ),
          isNotNull,
        );
      },
    );
  });

  group('ambushTopSectionGradient', () {
    test('is null for non-Ambush themes', () {
      expect(
        ambushTopSectionGradient('github-light', Brightness.light),
        isNull,
      );
      expect(ambushTopSectionGradient('nord', Brightness.dark), isNull);
    });

    test('paints top to bottom for both halves of the pair', () {
      for (final name in [ambushThemeName, ambushDarkThemeName]) {
        final gradient = ambushTopSectionGradient(name, Brightness.light);
        expect(gradient, isNotNull, reason: '$name should be gradient-backed');
        expect(gradient!.begin, Alignment.topCenter);
        expect(gradient.end, Alignment.bottomCenter);
        expect(gradient.colors, hasLength(2));
      }
    });

    test('brightness selects the stops, not the theme name', () {
      // Both halves enable the gradient, so System mode keeps it on across an
      // OS switch — the applied brightness alone decides which stops are used.
      final light = ambushTopSectionGradient(
        ambushThemeName,
        Brightness.light,
      )!;
      final dark = ambushTopSectionGradient(ambushThemeName, Brightness.dark)!;

      expect(light.colors, isNot(dark.colors));
      expect(
        ambushTopSectionGradient(ambushDarkThemeName, Brightness.dark)!.colors,
        dark.colors,
      );
      expect(
        ambushTopSectionGradient(ambushDarkThemeName, Brightness.light)!.colors,
        light.colors,
      );
    });

    test('is opaque so the color replaces the frosted fill', () {
      for (final brightness in Brightness.values) {
        final gradient = ambushTopSectionGradient(ambushThemeName, brightness)!;
        for (final color in gradient.colors) {
          expect(color.a, 1.0);
        }
      }
    });
  });

  group('theme threading', () {
    BoxDecoration barDecoration(WidgetTester tester) {
      final container = tester
          .widgetList<Container>(
            find.descendant(
              of: find.byType(FrostedAppBar),
              matching: find.byType(Container),
            ),
          )
          .first;
      return container.decoration! as BoxDecoration;
    }

    Widget harness(ThemeData theme) => MaterialApp(
      theme: theme,
      home: Builder(
        builder: (context) => Stack(
          children: [
            FrostedAppBar(
              gradient: context.appColors.topSectionGradient,
              title: const Text('Home'),
            ),
          ],
        ),
      ),
    );

    testWidgets('AppTheme carries the gradient to the top section', (
      tester,
    ) async {
      await tester.pumpWidget(
        harness(
          AppTheme.light(
            topSectionGradient: ambushTopSectionGradient(
              ambushThemeName,
              Brightness.light,
            ),
          ),
        ),
      );

      final decoration = barDecoration(tester);
      expect(decoration.gradient, isNotNull);
      // A BoxDecoration cannot paint a color and a gradient at once.
      expect(decoration.color, isNull);
    });

    testWidgets('non-Ambush themes keep the frosted surface fill', (
      tester,
    ) async {
      await tester.pumpWidget(harness(AppTheme.light()));

      final decoration = barDecoration(tester);
      expect(decoration.gradient, isNull);
      expect(decoration.color, isNotNull);
    });

    testWidgets('Ambush section labels use 80% neutral foreground', (
      tester,
    ) async {
      await tester.pumpWidget(
        harness(
          AppTheme.light(
            topSectionGradient: ambushTopSectionGradient(
              ambushThemeName,
              Brightness.light,
            ),
          ),
        ),
      );

      final context = tester.element(find.text('Home'));
      expect(
        navigationSectionForeground(context),
        Colors.black.withValues(alpha: 0.8),
      );
    });

    testWidgets('navigation roles inherit non-Ambush theme tokens', (
      tester,
    ) async {
      const primaryForeground = Color(0xFF123456);
      const secondaryForeground = Color(0xFF789ABC);
      const searchSurface = Color(0xFFDEF012);
      final theme = ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.purple).copyWith(
          onSurface: primaryForeground,
          onSurfaceVariant: secondaryForeground,
          surfaceContainerHighest: searchSurface,
        ),
      );

      await tester.pumpWidget(
        MaterialApp(
          theme: theme,
          home: const Scaffold(body: SizedBox()),
        ),
      );

      final context = tester.element(find.byType(SizedBox));
      expect(navigationPrimaryForeground(context), primaryForeground);
      expect(navigationSecondaryForeground(context), secondaryForeground);
      expect(navigationSectionForeground(context), secondaryForeground);
      expect(navigationSearchSurface(context), searchSurface);
      expect(
        navigationDivider(context, 0.15),
        primaryForeground.withValues(alpha: 0.15),
      );
    });
  });

  group('isAmbushTheme', () {
    test('matches only the Ambush pair', () {
      expect(isAmbushTheme(ambushThemeName), isTrue);
      expect(isAmbushTheme(ambushDarkThemeName), isTrue);
      expect(isAmbushTheme('github-light'), isFalse);
      expect(isAmbushTheme(''), isFalse);
    });
  });
}
