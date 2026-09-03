# Meadow Core

A minimal three-agent persona pack for Ambush.

| Agent | Role |
|-------|------|
| **Skip** | Orchestrator — coordinates the team, delegates work |
| **Lev** | Security reviewer — threat models, auth, injection |
| **Bana** | Architecture reviewer — big picture, simplicity |

## Usage

```bash
# Validate the pack
ambush pack validate ./examples/meadow-core

# Inspect resolved config
ambush pack inspect ./examples/meadow-core
```

The desktop app's Import button does not accept this pack directory or a zip of it — it imports
agent/team *snapshots* (`.agent.json`/`.team.json`, exported from agents already running in the
app), not persona-pack source. `ambush pack inspect` above shows the fully-resolved per-agent
config; use it as reference to recreate these agents in the desktop app by hand. Direct
persona-pack runtime integration is not currently implemented. See "Desktop App Import" in
`crates/ambush-persona/PERSONA_PACK_SPEC.md` for the current import paths.

## Structure

```
meadow-core/
├── .plugin/
│   └── plugin.json          # Pack manifest (OPS-compatible)
├── agents/
│   ├── skip.persona.md       # Orchestrator
│   ├── lev.persona.md        # Security reviewer
│   └── bana.persona.md       # Architecture reviewer
├── skills/
│   └── github-research/
│       └── SKILL.md          # GitHub search skill (shared)
├── instructions.md           # Team-wide instructions
└── README.md
```

## Customizing

Edit any `.persona.md` file to change the agent's behavior. The YAML
frontmatter controls config (model, triggers, channels). The markdown
body is the system prompt.

See `crates/ambush-persona/PERSONA_PACK_SPEC.md` for the full format reference.
