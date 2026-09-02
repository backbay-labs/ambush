part of '../pairing_page.dart';

class _OnboardingBackground extends StatelessWidget {
  final Widget child;

  const _OnboardingBackground({required this.child});

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      key: const Key('pairing-onboarding-background'),
      decoration: BoxDecoration(color: _onboardingGround),
      child: CustomPaint(painter: _DotGridPainter(), child: child),
    );
  }
}

class _DotGridPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final dotPaint = Paint()..color = _onboardingRule;
    const spacing = 24.0;

    for (var x = 0.0; x <= size.width; x += spacing) {
      for (var y = 0.0; y <= size.height; y += spacing) {
        canvas.drawCircle(Offset(x, y), 1, dotPaint);
      }
    }
  }

  @override
  bool shouldRepaint(_DotGridPainter oldDelegate) => false;
}
