import 'package:flutter/material.dart';
import 'package:highlight/highlight.dart' show highlight, Node;

import 'theme/quiet.dart';

/// Code inks: one lightness, low chroma, warm against cool.
///
/// Structure reads cool, literal content reads warm, and anything that names
/// something reads as plain ink — so a block stays legible by role position
/// with the hue stripped out. Comments recede to the engraved-label ink.
Map<String, TextStyle> _codeTheme(QuietSurfaces s, QuietCodeInks inks) {
  final structure = TextStyle(color: inks.cool);
  final literal = TextStyle(color: inks.warm);
  final name = TextStyle(color: s.ink);
  final aside = TextStyle(color: s.inkDim, fontStyle: FontStyle.italic);
  return {
    'keyword': structure,
    'built_in': structure,
    'type': structure,
    'operator': structure,
    'punctuation': structure,
    'literal': literal,
    'number': literal,
    'string': literal,
    'symbol': literal,
    'regexp': literal,
    'meta': literal,
    'attr': literal,
    'attribute': literal,
    'comment': aside,
    'doctag': aside,
    'quote': aside,
    'title': name,
    'title.class_': name,
    'title.function_': name,
    'name': name,
    'tag': name,
    'selector-tag': name,
    'selector-class': name,
    'selector-id': name,
    'variable': name,
    'template-variable': name,
    'subst': name,
    'params': TextStyle(color: s.inkMid),
    'section': TextStyle(color: s.ink, fontWeight: FontWeight.w600),
    'bullet': TextStyle(color: s.grad),
    'link': TextStyle(color: s.ink, decoration: TextDecoration.underline),
    'strong': const TextStyle(fontWeight: FontWeight.w600),
    'emphasis': const TextStyle(fontStyle: FontStyle.italic),
    'addition': TextStyle(color: s.ink),
    'deletion': TextStyle(color: s.inkDim),
  };
}

final highlightLightTheme = _codeTheme(quietDay, quietDayInks);
final highlightDarkTheme = _codeTheme(quietNight, quietNightInks);

List<InlineSpan> highlightCode(
  String code,
  String language,
  Map<String, TextStyle> theme,
  TextStyle baseStyle,
) {
  try {
    if (language.isEmpty) return [TextSpan(text: code, style: baseStyle)];
    final result = highlight.parse(code, language: language);
    if (result.nodes == null) return [TextSpan(text: code, style: baseStyle)];
    return buildSpans(result.nodes!, theme, baseStyle);
  } catch (_) {
    return [TextSpan(text: code, style: baseStyle)];
  }
}

List<InlineSpan> buildSpans(
  List<Node> nodes,
  Map<String, TextStyle> theme,
  TextStyle baseStyle, {
  int maxDepth = 10,
}) {
  final spans = <InlineSpan>[];
  for (final node in nodes) {
    if (maxDepth <= 0) {
      if (node.value != null) {
        spans.add(TextSpan(text: node.value, style: baseStyle));
      }
      continue;
    }
    if (node.children != null && node.children!.isNotEmpty) {
      final childStyle = node.className != null
          ? baseStyle.merge(theme[node.className])
          : baseStyle;
      spans.addAll(
        buildSpans(node.children!, theme, childStyle, maxDepth: maxDepth - 1),
      );
    } else if (node.value != null) {
      final style = node.className != null
          ? baseStyle.merge(theme[node.className])
          : baseStyle;
      spans.add(TextSpan(text: node.value, style: style));
    }
  }
  return spans;
}
