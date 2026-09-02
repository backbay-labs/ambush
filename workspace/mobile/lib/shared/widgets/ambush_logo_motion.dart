import 'package:flutter/material.dart';

/// The Ambush mark: an index rule stepped once, at the instant its state
/// changed.
///
/// A single vertical rule runs the height of the frame and, at one instant,
/// displaces sideways by exactly its own width. Above the step is the part
/// still running; below it is the part already spent. Callers drive how far
/// each segment has been inked in, which lets one painter serve the static
/// mark and the pull-to-refresh indicator.
///
/// Inside the app the mark is furniture: it paints in one [color] rather than
/// the index hue, because a warm stroke here would say something is undecided
/// when nothing is.
class AmbushLogoMotion extends StatelessWidget {
  /// The rendered width of the mark's square frame.
  final double width;

  /// The color of both segments.
  final Color color;

  /// How far the live segment has been inked, from 0 to 1.
  final double liveProgress;

  /// How far the spent segment has been inked, from 0 to 1.
  final double spentProgress;

  const AmbushLogoMotion({
    required this.width,
    required this.color,
    this.liveProgress = 1,
    this.spentProgress = 1,
    super.key,
  });

  @override
  Widget build(BuildContext context) {
    return RepaintBoundary(
      child: CustomPaint(
        size: Size.square(width),
        painter: _AmbushMarkPainter(
          color: color,
          liveProgress: liveProgress,
          spentProgress: spentProgress,
        ),
      ),
    );
  }
}

class _AmbushMarkPainter extends CustomPainter {
  final Color color;
  final double liveProgress;
  final double spentProgress;

  const _AmbushMarkPainter({
    required this.color,
    required this.liveProgress,
    required this.spentProgress,
  });

  // The construction: a 256-unit square on a module of 8, stroke 64. The two
  // segments overlap by 16 so the rule reads as one rule displaced rather than
  // as two bars.
  static const _live = Rect.fromLTWH(64, 0, 64, 152);
  static const _spent = Rect.fromLTWH(128, 136, 64, 120);

  @override
  void paint(Canvas canvas, Size size) {
    final scale = size.shortestSide / 256;
    final paint = Paint()..color = color;

    canvas
      ..save()
      ..translate(
        (size.width - (256 * scale)) / 2,
        (size.height - (256 * scale)) / 2,
      )
      ..scale(scale);

    // Each segment inks down from its own top edge.
    void segment(Rect rect, double progress) {
      final inked = progress.clamp(0.0, 1.0);
      if (inked <= 0) return;
      canvas.drawRect(
        Rect.fromLTWH(rect.left, rect.top, rect.width, rect.height * inked),
        paint,
      );
    }

    segment(_live, liveProgress);
    segment(_spent, spentProgress);

    canvas.restore();
  }

  @override
  bool shouldRepaint(_AmbushMarkPainter oldDelegate) =>
      color != oldDelegate.color ||
      liveProgress != oldDelegate.liveProgress ||
      spentProgress != oldDelegate.spentProgress;
}

/// How far each segment has been inked at position [t] of one engrave cycle.
///
/// The live segment inks down from the top first and the spent segment follows
/// it; both then hold for the rest of the cycle. Matches the desktop keyframes.
({double live, double spent}) ambushEngraveProgress(double t) {
  final position = t.clamp(0.0, 1.0);
  return (
    live: _engraveSegment(position, 0, 0.26),
    spent: _engraveSegment(position, 0.20, 0.44),
  );
}

const _engraveCurve = Cubic(0.16, 1, 0.3, 1);

/// The duration of one engrave cycle.
const ambushEngraveCycle = Duration(milliseconds: 2100);

double _engraveSegment(double t, double start, double end) =>
    _engraveCurve.transform(((t - start) / (end - start)).clamp(0.0, 1.0));
