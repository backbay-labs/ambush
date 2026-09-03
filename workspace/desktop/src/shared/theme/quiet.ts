/**
 * Quiet — the Ambush design palette.
 *
 * The room is achromatic, the lamp is warm, and the one saturated value marks
 * an irreversible action that has not been decided yet. Ambush Night and
 * Ambush Day are the same material under two lighting conditions; each ships
 * as a full theme registration so the loader treats them exactly like a
 * bundled Shiki theme.
 */

import type { ThemeRegistrationRaw } from "shiki";
import type { ThemeSurfaces } from "./adaptive-theme";

export const QUIET_NIGHT: ThemeSurfaces = {
  mode: "dark",
  index: "#E05E28",
  night: "#171717",
  steel: "#1F1F1F",
  rule: "#3E3E3E",
  grad: "#727272",
  plate: "#33281E",
  plateHigh: "#3D3025",
  inkDim: "#A49B90",
  inkMid: "#BAB2A8",
  ink: "#C9C1B7",
};

export const QUIET_DAY: ThemeSurfaces = {
  mode: "light",
  index: "#943106",
  night: "#BCB5AD",
  steel: "#C7C0B8",
  rule: "#9C9893",
  grad: "#7A7672",
  plate: "#ECCFB9",
  plateHigh: "#F4D7C4",
  inkDim: "#51443A",
  inkMid: "#3E332A",
  ink: "#292019",
};

/**
 * Syntax and terminal inks: one lightness, low chroma, warm against cool.
 * Structure reads cool, literal content reads warm, everything a name reads
 * as plain ink — so code stays legible with the hue stripped out.
 */
type CodeInks = {
  warm: string;
  cool: string;
  ansi: Record<string, string>;
};

const NIGHT_INKS: CodeInks = {
  warm: "#C4AFA2",
  cool: "#A1B6C6",
  ansi: {
    "terminal.ansiBlack": "#3E3E3E",
    "terminal.ansiRed": "#C9ADAB",
    "terminal.ansiGreen": "#A8B7A6",
    "terminal.ansiYellow": "#C0B1A0",
    "terminal.ansiBlue": "#A3B5C6",
    "terminal.ansiMagenta": "#BDAFC0",
    "terminal.ansiCyan": "#9AB9BA",
    "terminal.ansiWhite": "#BAB2A8",
    "terminal.ansiBrightBlack": "#727272",
    "terminal.ansiBrightRed": "#D8BBBA",
    "terminal.ansiBrightGreen": "#B7C6B4",
    "terminal.ansiBrightYellow": "#CFBFAE",
    "terminal.ansiBrightBlue": "#B2C4D5",
    "terminal.ansiBrightMagenta": "#CCBDCF",
    "terminal.ansiBrightCyan": "#A9C8C8",
    "terminal.ansiBrightWhite": "#C9C1B7",
  },
};

const DAY_INKS: CodeInks = {
  warm: "#453126",
  cool: "#1F3847",
  ansi: {
    "terminal.ansiBlack": "#292019",
    "terminal.ansiRed": "#482E2D",
    "terminal.ansiGreen": "#2A3928",
    "terminal.ansiYellow": "#403323",
    "terminal.ansiBlue": "#223747",
    "terminal.ansiMagenta": "#3E3041",
    "terminal.ansiCyan": "#173A3B",
    "terminal.ansiWhite": "#9C9893",
    "terminal.ansiBrightBlack": "#7A7672",
    "terminal.ansiBrightRed": "#3A2221",
    "terminal.ansiBrightGreen": "#1E2C1C",
    "terminal.ansiBrightYellow": "#322616",
    "terminal.ansiBrightBlue": "#142A3A",
    "terminal.ansiBrightMagenta": "#312434",
    "terminal.ansiBrightCyan": "#082D2E",
    "terminal.ansiBrightWhite": "#C7C0B8",
  },
};

function quietTheme(
  name: string,
  surfaces: ThemeSurfaces,
  inks: CodeInks,
): ThemeRegistrationRaw & { surfaces: ThemeSurfaces } {
  return {
    name,
    type: surfaces.mode,
    surfaces,
    colors: {
      "editor.background": surfaces.steel,
      "editor.foreground": surfaces.inkMid,
      "editor.lineHighlightBackground": surfaces.plate,
      "editorLineNumber.foreground": surfaces.grad,
      "editorIndentGuide.background": surfaces.rule,
      "terminalCursor.foreground": surfaces.ink,
      "terminalCursor.background": surfaces.steel,
      "gitDecoration.addedResourceForeground": surfaces.ink,
      "gitDecoration.deletedResourceForeground": surfaces.inkDim,
      "gitDecoration.modifiedResourceForeground": surfaces.inkMid,
      ...inks.ansi,
    },
    settings: [
      { settings: { background: surfaces.steel, foreground: surfaces.inkMid } },
      {
        scope: ["comment", "punctuation.definition.comment"],
        settings: { foreground: surfaces.inkDim, fontStyle: "italic" },
      },
      {
        scope: [
          "keyword",
          "storage",
          "storage.type",
          "keyword.control",
          "keyword.operator",
          "punctuation",
          "meta.brace",
        ],
        settings: { foreground: inks.cool },
      },
      {
        scope: [
          "string",
          "string.quoted",
          "constant.numeric",
          "constant.language",
          "constant.character.escape",
          "markup.inline.raw",
        ],
        settings: { foreground: inks.warm },
      },
      {
        scope: [
          "entity.name.function",
          "support.function",
          "entity.name.type",
          "support.type",
          "support.class",
          "variable",
          "variable.parameter",
          "entity.name.tag",
          "meta.attribute",
        ],
        settings: { foreground: surfaces.ink },
      },
      {
        scope: ["invalid", "invalid.illegal"],
        settings: { foreground: surfaces.ink, fontStyle: "underline" },
      },
      {
        scope: ["markup.inserted"],
        settings: { foreground: surfaces.ink },
      },
      {
        scope: ["markup.deleted"],
        settings: { foreground: surfaces.inkDim },
      },
    ],
  };
}

export const AMBUSH_NIGHT_THEME = quietTheme(
  "ambush-night",
  QUIET_NIGHT,
  NIGHT_INKS,
);

export const AMBUSH_DAY_THEME = quietTheme("ambush-day", QUIET_DAY, DAY_INKS);
