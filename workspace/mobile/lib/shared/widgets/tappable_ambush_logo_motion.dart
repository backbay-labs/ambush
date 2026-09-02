import 'package:flutter/material.dart';
import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';

import 'ambush_logo_motion.dart';

/// The Ambush mark, re-engraved when the user taps it.
///
/// The rule inks down from the top once per tap and then holds. When reduced
/// motion is enabled the mark stays finished and still.
class TappableAmbushLogoMotion extends HookConsumerWidget {
  /// The rendered width of the mark's square frame.
  final double width;

  /// The color of both segments.
  final Color color;

  const TappableAmbushLogoMotion({
    required this.width,
    required this.color,
    super.key,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final animation = useAnimationController(duration: ambushEngraveCycle);
    final reducedMotion = MediaQuery.disableAnimationsOf(context);

    void engrave() {
      if (reducedMotion) return;
      animation.forward(from: 0);
    }

    return Semantics(
      button: true,
      label: 'Ambush mark',
      hint: 'Tap to redraw it',
      onTap: engrave,
      child: GestureDetector(
        behavior: HitTestBehavior.opaque,
        excludeFromSemantics: true,
        onTap: engrave,
        child: RepaintBoundary(
          child: AnimatedBuilder(
            animation: animation,
            builder: (context, _) {
              final progress = ambushEngraveProgress(
                animation.isAnimating ? animation.value : 1,
              );
              return AmbushLogoMotion(
                width: width,
                color: color,
                liveProgress: progress.live,
                spentProgress: progress.spent,
              );
            },
          ),
        ),
      ),
    );
  }
}
