import 'dart:async' show unawaited;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';

import '../theme/theme.dart';
import 'ambush_logo_motion.dart';

/// Replaces the standard pull-to-refresh spinner with the Ambush mark.
///
/// Flutter continues to own the gesture, refresh lifecycle, and accessibility
/// semantics. This widget maps those states into the elastic pull, retained
/// loading gap, and the mark's engraving: the rule inks down under the finger
/// and keeps re-engraving while the load is in flight, so the motion always
/// means something is happening.
class AmbushRefreshIndicator extends HookConsumerWidget {
  /// Called when the user completes a pull, to load fresh data.
  ///
  /// The mark keeps engraving until this future settles, so it should complete
  /// only once the refresh is done.
  final Future<void> Function() onRefresh;

  /// The scrollable this indicator wraps.
  ///
  /// It must scroll vertically; the indicator reads its scroll notifications
  /// to couple the mark to the user's finger.
  final Widget child;

  /// The vertical offset of the scrollable's top edge, such as a pinned header.
  final double edgeOffset;

  const AmbushRefreshIndicator({
    required this.onRefresh,
    required this.child,
    this.edgeOffset = 0,
    super.key,
  });

  static const _markSize = 44.0;
  static const _triggerDistance = 100.0;
  static const _loadingGap = 72.0;
  static const _markVerticalAlignment = 0.75;
  static const _markInitialScale = 0.6;
  static const _markRevealStartProgress = 0.18;
  static const _settleDuration = Duration(milliseconds: 180);

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final status = useState<RefreshIndicatorStatus?>(null);
    final pullProgress = useState(0.0);
    final pullDistance = useState(0.0);
    final didTriggerArmHaptic = useRef(false);
    final completionController = useAnimationController(
      duration: _settleDuration,
    );
    final gapController = useAnimationController(
      duration: _settleDuration,
      reverseDuration: _settleDuration,
    );
    final engraveController = useAnimationController(
      duration: ambushEngraveCycle,
    );
    final completionProgress = useAnimation(completionController);
    final gapProgress = useAnimation(gapController);
    final engraveCycle = useAnimation(engraveController);
    final reducedMotion = MediaQuery.disableAnimationsOf(context);

    void armHaptic() {
      if (didTriggerArmHaptic.value) return;
      didTriggerArmHaptic.value = true;
      unawaited(HapticFeedback.mediumImpact());
    }

    void updateStatus(RefreshIndicatorStatus? nextStatus) {
      status.value = nextStatus;

      if (nextStatus == RefreshIndicatorStatus.drag) {
        completionController.reset();
        gapController.reset();
        engraveController.stop();
      } else if (nextStatus == RefreshIndicatorStatus.armed) {
        pullProgress.value = 1;
        armHaptic();
      } else if (nextStatus == RefreshIndicatorStatus.snap ||
          nextStatus == RefreshIndicatorStatus.refresh) {
        pullProgress.value = 1;
        if (reducedMotion) {
          gapController.value = 1;
        } else {
          gapController.animateTo(1, curve: Curves.easeOutCubic);
          engraveController.repeat();
        }
      } else if (nextStatus == RefreshIndicatorStatus.done) {
        if (reducedMotion) {
          gapController.value = 0;
          pullProgress.value = 0;
          pullDistance.value = 0;
          status.value = null;
        } else {
          engraveController.repeat();
          gapController
              .animateTo(1, curve: Curves.easeOutCubic)
              .whenCompleteOrCancel(() {
                if (!gapController.isCompleted || status.value == null) return;
                gapController.animateBack(0, curve: Curves.easeInOutCubic);
                completionController.forward(from: 0).whenCompleteOrCancel(() {
                  if (!completionController.isCompleted) return;
                  engraveController.stop();
                  pullProgress.value = 0;
                  pullDistance.value = 0;
                  status.value = null;
                });
              });
        }
      } else if (nextStatus == RefreshIndicatorStatus.canceled ||
          nextStatus == null) {
        pullProgress.value = 0;
        pullDistance.value = 0;
        if (!gapController.isAnimating) gapController.reset();
        engraveController.stop();
      }
    }

    bool trackPull(ScrollNotification notification) {
      if (notification.metrics.axis != Axis.vertical) return false;

      if (notification is! ScrollStartNotification &&
          notification.metrics.extentBefore == 0) {
        // BouncingScrollPhysics reports a live negative scroll position while
        // the user is pulling. Reading it keeps the mark coupled to the finger.
        final elasticPull =
            (notification.metrics.minScrollExtent - notification.metrics.pixels)
                .clamp(0.0, double.infinity)
                .toDouble();
        if (elasticPull > 0 || pullDistance.value > 0) {
          pullDistance.value = elasticPull;
          final nextProgress = (elasticPull / _triggerDistance).clamp(0.0, 1.0);
          pullProgress.value = nextProgress;
          if (nextProgress >= 1) armHaptic();
        } else if (notification case OverscrollNotification()) {
          // Clamping physics does not expose a negative position, so build the
          // same progress from its overscroll deltas.
          final nextDistance =
              pullDistance.value + notification.overscroll.abs();
          pullDistance.value = nextDistance;
          pullProgress.value = (nextDistance / _triggerDistance).clamp(
            0.0,
            1.0,
          );
          if (pullProgress.value >= 1) armHaptic();
        }
      }
      return false;
    }

    void startPointer(PointerDownEvent event) {
      didTriggerArmHaptic.value = false;
      pullProgress.value = 0;
      pullDistance.value = 0;
    }

    final isLoading = switch (status.value) {
      RefreshIndicatorStatus.snap ||
      RefreshIndicatorStatus.refresh ||
      RefreshIndicatorStatus.done => true,
      _ => false,
    };
    final dragRevealProgress =
        ((pullProgress.value - _markRevealStartProgress) /
                (1 - _markRevealStartProgress))
            .clamp(0.0, 1.0);
    final isVisible =
        status.value != null &&
        (isLoading || dragRevealProgress > 0 || completionProgress > 0);
    final retainedGap = _loadingGap * gapProgress;
    final visibleGap = pullDistance.value + retainedGap;
    final top = edgeOffset + (visibleGap - _markSize) * _markVerticalAlignment;
    final opacity = isLoading ? 1 - completionProgress : dragRevealProgress;
    final markScale = isLoading
        ? 1.0
        : _markInitialScale + (1 - _markInitialScale) * dragRevealProgress;
    // Under the finger the rule inks with the pull; in flight it re-engraves.
    final engrave = reducedMotion
        ? ambushEngraveProgress(1)
        : isLoading
        ? ambushEngraveProgress(engraveCycle)
        : ambushEngraveProgress(pullProgress.value * 0.44);
    final scrollBehavior = ScrollConfiguration.of(context).copyWith(
      overscroll: false,
      physics: const BouncingScrollPhysics(
        parent: AlwaysScrollableScrollPhysics(),
      ),
    );

    return Stack(
      clipBehavior: Clip.none,
      children: [
        RefreshIndicator.noSpinner(
          onRefresh: onRefresh,
          onStatusChange: updateStatus,
          semanticsLabel: 'Pull to refresh',
          child: NotificationListener<ScrollNotification>(
            onNotification: trackPull,
            child: Listener(
              behavior: HitTestBehavior.translucent,
              onPointerDown: startPointer,
              child: ScrollConfiguration(
                behavior: scrollBehavior,
                child: Transform.translate(
                  key: const ValueKey('refresh-retained-gap'),
                  offset: Offset(0, retainedGap),
                  child: child,
                ),
              ),
            ),
          ),
        ),
        if (isVisible)
          Positioned(
            top: edgeOffset,
            left: 0,
            right: 0,
            bottom: 0,
            child: ClipRect(
              child: Align(
                alignment: Alignment.topCenter,
                child: Transform.translate(
                  offset: Offset(0, top - edgeOffset),
                  child: IgnorePointer(
                    child: Opacity(
                      key: const ValueKey('refresh-opacity'),
                      opacity: opacity.clamp(0.0, 1.0),
                      child: Transform.scale(
                        key: const ValueKey('refresh-scale'),
                        scale: markScale,
                        child: AmbushLogoMotion(
                          width: _markSize,
                          color: context.colors.primary,
                          liveProgress: engrave.live,
                          spentProgress: engrave.spent,
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),
      ],
    );
  }
}
