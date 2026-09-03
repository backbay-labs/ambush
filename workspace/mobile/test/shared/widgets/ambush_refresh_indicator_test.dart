import 'dart:async';
import 'dart:ui' as ui;

import 'package:ambush/shared/widgets/ambush_refresh_indicator.dart';
import 'package:ambush/shared/widgets/ambush_logo_motion.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import '../../helpers/widget_helpers.dart';

void main() {
  testWidgets('inks both segments of the rule when fully engraved', (
    tester,
  ) async {
    const markKey = ValueKey('engraved-mark');
    await tester.pumpWidget(
      const MaterialApp(
        home: Center(
          child: AmbushLogoMotion(
            key: markKey,
            width: 256,
            color: Colors.black,
          ),
        ),
      ),
    );

    final boundary = tester.renderObject<RenderRepaintBoundary>(
      find.descendant(
        of: find.byKey(markKey),
        matching: find.byType(RepaintBoundary),
      ),
    );
    final bytes = await tester.runAsync(() async {
      final image = await boundary.toImage();
      final data = await image.toByteData(format: ui.ImageByteFormat.rawRgba);
      image.dispose();
      return data;
    });
    expect(bytes, isNotNull);

    int alphaAt(int x, int y) => bytes!.getUint8(((y * 256) + x) * 4 + 3);

    // The live segment runs from the top of the frame, the spent segment
    // displaces one stroke to the right and runs to the foot, and the channel
    // between them is empty above the step.
    expect(alphaAt(96, 20), 255);
    expect(alphaAt(160, 240), 255);
    expect(alphaAt(160, 20), 0);
    expect(alphaAt(96, 240), 0);
  });

  testWidgets('shows the mark while pulling to refresh', (tester) async {
    const contentKey = ValueKey('loading-content');
    var refreshes = 0;
    final refreshCompleter = Completer<void>();

    await tester.pumpWidget(
      WidgetHelpers.testable(
        child: AmbushRefreshIndicator(
          onRefresh: () {
            refreshes++;
            return refreshCompleter.future;
          },
          child: ListView(
            children: const [SizedBox(key: contentKey, height: 800)],
          ),
        ),
      ),
    );

    final listFinder = find.byType(ListView);
    final restingTop = tester.getTopLeft(listFinder).dy;
    final restingContentTop = tester.getTopLeft(find.byKey(contentKey)).dy;
    await tester.timedDrag(
      listFinder,
      const Offset(0, 320),
      const Duration(milliseconds: 500),
    );
    await tester.pump(const Duration(milliseconds: 16));
    await tester.pump(const Duration(milliseconds: 300));

    final markFinder = find.byType(AmbushLogoMotion);
    final loadingTop = tester.getTopLeft(listFinder).dy;
    final loadingContentTop = tester.getTopLeft(find.byKey(contentKey)).dy;
    final gapTransform = tester.widget<Transform>(
      find.byKey(const ValueKey('refresh-retained-gap')),
    );
    expect(markFinder, findsOneWidget);
    expect(refreshes, 1);
    expect(gapTransform.transform.getTranslation().y, closeTo(72, 1));
    expect(loadingTop - restingTop, closeTo(72, 1));
    final loadingMarkRect = tester.getRect(markFinder);
    final loadingGap = loadingContentTop - restingContentTop;
    expect(
      loadingMarkRect.center.dy,
      closeTo(
        restingContentTop +
            (loadingGap - loadingMarkRect.height) * 0.75 +
            loadingMarkRect.height / 2,
        1,
      ),
    );

    refreshCompleter.complete();
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 90));

    final closingTop = tester.getTopLeft(listFinder).dy;
    expect(closingTop, greaterThan(restingTop));
    expect(closingTop, lessThan(loadingTop));

    await tester.pumpAndSettle();
    expect(tester.getTopLeft(listFinder).dy, closeTo(restingTop, 1));
    expect(markFinder, findsNothing);
  });

  testWidgets('engraves the rule as the pull deepens', (tester) async {
    tester.view.physicalSize = const Size(420, 912);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final hapticCalls = <MethodCall>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
          if (call.method == 'HapticFeedback.vibrate') hapticCalls.add(call);
          return null;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, null),
    );

    const contentKey = ValueKey('pull-content');
    final refreshCompleter = Completer<void>();
    await tester.pumpWidget(
      WidgetHelpers.testable(
        child: AmbushRefreshIndicator(
          onRefresh: () => refreshCompleter.future,
          child: ListView(
            children: const [SizedBox(key: contentKey, height: 800)],
          ),
        ),
      ),
    );

    final restingContentTop = tester.getTopLeft(find.byKey(contentKey)).dy;
    final gesture = await tester.startGesture(
      tester.getCenter(find.byType(ListView)),
      pointer: 1,
    );
    await gesture.moveBy(const Offset(0, 12));
    await tester.pump();

    final markFinder = find.byType(AmbushLogoMotion);
    expect(markFinder, findsNothing);
    expect(
      tester.getTopLeft(find.byKey(contentKey)).dy,
      greaterThan(restingContentTop),
    );

    await gesture.moveBy(const Offset(0, 44));
    await tester.pump();

    final earlyTop = tester.getTopLeft(markFinder).dy;
    final partialOpacity = tester.widget<Opacity>(
      find.byKey(const ValueKey('refresh-opacity')),
    );
    expect(partialOpacity.opacity, greaterThan(0));
    expect(partialOpacity.opacity, lessThan(1));
    final partialScale = tester
        .widget<Transform>(find.byKey(const ValueKey('refresh-scale')))
        .transform
        .storage[0];
    expect(partialScale, greaterThan(0.6));
    expect(partialScale, lessThan(1));
    final earlyLive = tester.widget<AmbushLogoMotion>(markFinder).liveProgress;
    expect(earlyLive, greaterThan(0));
    expect(earlyLive, lessThan(1));
    expect(hapticCalls, isEmpty);

    await gesture.moveBy(const Offset(0, 120));
    await tester.pump();

    final pulledContentTop = tester.getTopLeft(find.byKey(contentKey)).dy;
    expect(tester.getTopLeft(markFinder).dy, greaterThan(earlyTop));
    expect(
      tester.widget<AmbushLogoMotion>(markFinder).liveProgress,
      greaterThan(earlyLive),
    );
    final pulledMarkRect = tester.getRect(markFinder);
    final pulledGap = pulledContentTop - restingContentTop;
    expect(
      pulledMarkRect.center.dy,
      closeTo(
        restingContentTop +
            (pulledGap - pulledMarkRect.height) * 0.75 +
            pulledMarkRect.height / 2,
        1,
      ),
    );

    await gesture.moveBy(const Offset(0, 120));
    await tester.pump();

    expect(
      tester
          .widget<Transform>(find.byKey(const ValueKey('refresh-scale')))
          .transform
          .storage[0],
      closeTo(1, 0.001),
    );
    // Arming is the one haptic in the gesture, and it fires exactly once.
    expect(hapticCalls, hasLength(1));
    expect(hapticCalls.single.arguments, 'HapticFeedbackType.mediumImpact');

    await gesture.moveBy(const Offset(0, 240));
    await tester.pump();
    expect(hapticCalls, hasLength(1));

    await gesture.up();
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 300));
    expect(hapticCalls, hasLength(1));

    refreshCompleter.complete();
    await tester.pumpAndSettle();
  });

  testWidgets('arms once for a quick refresh flick', (tester) async {
    final hapticCalls = <MethodCall>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
          if (call.method == 'HapticFeedback.vibrate') hapticCalls.add(call);
          return null;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, null),
    );
    final refreshCompleter = Completer<void>();
    var refreshes = 0;
    await tester.pumpWidget(
      WidgetHelpers.testable(
        child: AmbushRefreshIndicator(
          onRefresh: () {
            refreshes++;
            return refreshCompleter.future;
          },
          child: ListView(children: const [SizedBox(height: 800)]),
        ),
      ),
    );

    final gesture = await tester.startGesture(
      tester.getCenter(find.byType(ListView)),
    );
    for (var step = 0; step < 10; step++) {
      await gesture.moveBy(
        const Offset(0, 50),
        timeStamp: Duration(milliseconds: (step + 1) * 10),
      );
      await tester.pump(const Duration(milliseconds: 10));
    }

    await gesture.up();
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 300));

    expect(refreshes, 1);
    expect(hapticCalls, hasLength(1));
    expect(hapticCalls.single.arguments, 'HapticFeedbackType.mediumImpact');

    refreshCompleter.complete();
    await tester.pumpAndSettle();
  });

  testWidgets('leaves the mark finished when motion is disabled', (
    tester,
  ) async {
    await tester.pumpWidget(
      MediaQuery(
        data: const MediaQueryData(disableAnimations: true),
        child: WidgetHelpers.testable(
          child: Builder(
            builder: (context) => MediaQuery(
              data: MediaQuery.of(context).copyWith(disableAnimations: true),
              child: AmbushRefreshIndicator(
                onRefresh: () async {},
                child: ListView(children: const [SizedBox(height: 800)]),
              ),
            ),
          ),
        ),
      ),
    );

    await tester.timedDrag(
      find.byType(ListView),
      const Offset(0, 160),
      const Duration(milliseconds: 400),
    );
    await tester.pump();

    final mark = tester.widget<AmbushLogoMotion>(find.byType(AmbushLogoMotion));
    expect(mark.liveProgress, 1);
    expect(mark.spentProgress, 1);
  });

  testWidgets('provides elastic always-scrollable physics', (tester) async {
    late ScrollPhysics physics;

    await tester.pumpWidget(
      WidgetHelpers.testable(
        child: AmbushRefreshIndicator(
          onRefresh: () async {},
          child: Builder(
            builder: (context) {
              physics = ScrollConfiguration.of(
                context,
              ).getScrollPhysics(context);
              return ListView(children: const [SizedBox(height: 20)]);
            },
          ),
        ),
      ),
    );

    expect(physics, isA<BouncingScrollPhysics>());
    expect(physics.parent, isA<AlwaysScrollableScrollPhysics>());
  });
}
