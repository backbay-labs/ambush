import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import '../theme/theme.dart';
import 'ambush_navigation_metrics.dart';
import 'ios_glass_navigation_button.dart';

/// A titled sheet header with balanced actions and an exactly centered title.
class AmbushSheetHeader extends StatelessWidget {
  const AmbushSheetHeader({
    super.key,
    this.title,
    this.titleKey,
    this.leading,
    this.trailing,
    this.showDragHandle = false,
  });

  final String? title;
  final Key? titleKey;
  final Widget? leading;
  final Widget? trailing;
  final bool showDragHandle;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(
        top: Grid.xxs,
        left: Grid.gutter,
        right: Grid.gutter,
        bottom: Grid.xs,
      ),
      child: SizedBox(
        height: ambushNavigationRowHeight,
        child: Stack(
          alignment: Alignment.topCenter,
          children: [
            if (showDragHandle) const _SheetDragHandle(),
            if (title case final title?)
              Positioned(
                left: 64,
                right: 64,
                bottom: 0,
                height: 44,
                child: Center(
                  child: Text(
                    title,
                    key: titleKey ?? const ValueKey('ambush-sheet-title'),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    textAlign: TextAlign.center,
                    style: context.textTheme.titleSmall?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ),
            Align(
              alignment: Alignment.bottomRight,
              child: trailing ?? const _SheetCloseButton(),
            ),
            if (leading case final leading?)
              Align(alignment: Alignment.bottomLeft, child: leading),
          ],
        ),
      ),
    );
  }
}

class _SheetCloseButton extends StatelessWidget {
  const _SheetCloseButton();

  @override
  Widget build(BuildContext context) {
    void closeSheet() {
      unawaited(HapticFeedback.lightImpact());
      Navigator.of(context).pop();
    }

    if (Theme.of(context).platform == TargetPlatform.iOS) {
      return IosGlassNavigationButton(
        key: const ValueKey('ambush-sheet-ios-glass-close'),
        icon: IosGlassNavigationIcon.close,
        semanticLabel: 'Close sheet',
        onPressed: closeSheet,
        width: ambushNavigationActionSize,
        height: ambushNavigationActionSize,
        foregroundColor: context.colors.primary,
      );
    }

    return SizedBox.square(
      dimension: ambushNavigationActionSize,
      child: IconButton(
        tooltip: 'Close sheet',
        onPressed: closeSheet,
        style: IconButton.styleFrom(
          padding: EdgeInsets.zero,
          backgroundColor: context.colors.surfaceContainerHighest,
          foregroundColor: context.colors.primary,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(Radii.dialog),
          ),
        ),
        icon: const Icon(LucideIcons.x, size: 22),
      ),
    );
  }
}

class _SheetDragHandle extends StatelessWidget {
  const _SheetDragHandle();

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: MaterialLocalizations.of(context).modalBarrierDismissLabel,
      container: true,
      button: true,
      onTap: () => Navigator.of(context).pop(),
      child: Container(
        key: const ValueKey('ambush-sheet-drag-handle'),
        width: 32,
        height: 4,
        decoration: BoxDecoration(
          color: context.colors.onSurfaceVariant.withValues(alpha: 0.4),
          borderRadius: BorderRadius.circular(Radii.full),
        ),
      ),
    );
  }
}
