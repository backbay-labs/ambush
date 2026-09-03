/** @type {import('tailwindcss').Config} */
export default {
  theme: {
    extend: {
      // Sub-`text-xs` ramp for meta text (timestamps, count badges, tracking
      // labels) and tiny glyphs. These follow the virtual typography rem
      // (`--ambush-type-rem` in styles/globals/typography.css), which is
      // rem-relative: Cmd +/- zooms it with the rest of the layout, and the
      // Font size preference nudges it alone. Do NOT reintroduce arbitrary `text-[…rem]` / `text-[…px]` literals;
      // the px-text guard rejects them. Stock scale picks up from xs.
      fontSize: {
        "2xs": "calc(var(--ambush-type-rem) * 0.6875)", // 11px at 16px type rem
        "3xs": "calc(var(--ambush-type-rem) * 0.5)", // 8px at 16px type rem
        badge: "calc(var(--ambush-type-rem) * 0.625)", // 10px at 16px type rem
        // Shared channel, DM, thread, and composer type. Variables keep app-wide
        // font size and keyboard zoom consistent without branching components.
        message: [
          "var(--conversation-message-font-size)",
          { lineHeight: "var(--conversation-message-line-height)" },
        ],
        "message-timestamp": [
          "var(--conversation-timestamp-font-size)",
          { lineHeight: "var(--conversation-timestamp-line-height)" },
        ],
        // 40px at the 16px type rem — onboarding page titles.
        title: [
          "calc(var(--ambush-type-rem) * 2.5)",
          { lineHeight: "1.15", letterSpacing: "-0.02em" },
        ],
        // 36px at the 16px type rem — backup-step private key.
        "nsec-key": [
          "calc(var(--ambush-type-rem) * 2.25)",
          { lineHeight: "1.3" },
        ],
      },
      lineHeight: {
        // Keep fixed Tailwind line-height utilities in the typography scale so
        // Cmd +/- cannot enlarge glyphs inside an unchanged line box. Single-
        // line surfaces keep their existing truncate/overflow behavior.
        3: "calc(var(--ambush-type-rem) * 0.75)",
        4: "var(--ambush-type-rem)",
        5: "calc(var(--ambush-type-rem) * 1.25)",
        6: "calc(var(--ambush-type-rem) * 1.5)",
        7: "calc(var(--ambush-type-rem) * 1.75)",
        8: "calc(var(--ambush-type-rem) * 2)",
        "message-author": "var(--conversation-author-line-height)",
      },
      // Separation is drawn, never blurred: surfaces are told apart by a
      // hairline and by a step in lightness. The stock scale collapses so a
      // stray `shadow-lg` cannot reintroduce a glow.
      boxShadow: {
        "2xs": "none",
        xs: "none",
        sm: "none",
        DEFAULT: "none",
        md: "none",
        lg: "none",
        xl: "none",
        "2xl": "none",
        "content-edge": "-1px -1px 0 0 hsl(var(--sidebar-border))",
        // A left-facing boundary. Tailwind's stock shadows are all y-offset,
        // so they cast almost nothing sideways; this draws the edge the panel
        // actually exposes, turning its rounded corners with it.
        "panel-left": "-1px 0 0 0 hsl(var(--border))",
      },
      // A machined chamfer, uniform everywhere. Circles stay circles.
      borderRadius: {
        none: "0px",
        xs: "var(--radius)",
        sm: "var(--radius)",
        DEFAULT: "var(--radius)",
        md: "var(--radius)",
        lg: "var(--radius)",
        xl: "var(--radius)",
        "2xl": "var(--radius)",
        "3xl": "var(--radius)",
        "4xl": "var(--radius)",
        full: "9999px",
      },
      spacing: {
        4.5: "1.125rem",
        "conversation-body": "var(--conversation-body-gap)",
        "conversation-list": "var(--conversation-list-item-gap)",
        "conversation-paragraph": "var(--conversation-paragraph-gap)",
        "conversation-row": "var(--conversation-row-padding-block)",
      },
      fontFamily: {
        sans: [
          '"IBM Plex Sans Variable"',
          '"IBM Plex Sans"',
          '"Helvetica Neue"',
          "Helvetica",
          "Arial",
          "sans-serif",
        ],
        mono: [
          '"IBM Plex Mono"',
          "ui-monospace",
          '"SF Mono"',
          "Menlo",
          "monospace",
        ],
      },
      colors: {
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        sidebar: {
          DEFAULT: "hsl(var(--sidebar-background))",
          foreground: "hsl(var(--sidebar-foreground))",
          primary: "hsl(var(--sidebar-primary))",
          "primary-foreground": "hsl(var(--sidebar-primary-foreground))",
          active: "hsl(var(--sidebar-active))",
          "active-foreground": "hsl(var(--sidebar-active-foreground))",
          accent: "hsl(var(--sidebar-accent))",
          "accent-foreground": "hsl(var(--sidebar-accent-foreground))",
          border: "hsl(var(--sidebar-border))",
          ring: "hsl(var(--sidebar-ring))",
        },
        status: {
          added: "var(--status-added)",
          deleted: "var(--status-deleted)",
          modified: "var(--status-modified)",
        },
        warning: {
          DEFAULT: "var(--ui-warning)",
          bg: "var(--ui-warning-bg)",
        },
        // The Quiet palette itself. Reach for a semantic token above when one
        // fits; these are for the roles shadcn has no name for — the index
        // mark, the plate's raised head, graduations, and mid ink.
        index: "var(--ambush-index)",
        night: "var(--ambush-night)",
        steel: "var(--ambush-steel)",
        rule: "var(--ambush-rule)",
        grad: "var(--ambush-grad)",
        plate: {
          DEFAULT: "var(--ambush-plate)",
          hi: "var(--ambush-plate-hi)",
        },
        ink: {
          DEFAULT: "var(--ambush-ink)",
          mid: "var(--ambush-ink-mid)",
          dim: "var(--ambush-ink-dim)",
        },
      },
    },
  },
  plugins: [],
};
