# Ika Claude Code Skills

[Claude Code skills](https://docs.anthropic.com/en/docs/claude-code/skills) for working with the Ika network. Each skill provides compressed, LLM-optimized reference material that Claude Code loads on demand.

## Available Skills

| Skill | Description |
|---|---|
| [ika-move](./ika-move/) | Integrating with Ika dWallet contracts in Sui Move — DKG, presign, signing, key import, treasury patterns |
| [ika-sdk](./ika-sdk/) | Building with the `@ika.xyz/sdk` TypeScript SDK — IkaClient, IkaTransaction, cryptography, dWallet lifecycle |
| [ika-operator](./ika-operator/) | Operating Ika network nodes — validator setup, fullnode/notifier config, monitoring, recovery |

## Installation

### For this repo (automatic)

Skills in this directory are automatically available to Claude Code when working in this repository.

### For other projects

Copy the desired skill folder into your project's `skills/` directory or into `~/.claude/skills/` for global availability:

```bash
# Project-local
cp -r skills/ika-sdk /path/to/your-project/skills/

# Global
cp -r skills/ika-sdk ~/.claude/skills/
```

## Structure

Each skill follows the same pattern:

```
skills/<skill-name>/
├── SKILL.md              # Main reference (loaded into context on trigger)
└── references/           # Detailed docs (loaded on demand)
    ├── *.md
    └── ...
```

- **SKILL.md** — Quick reference with the most common patterns and APIs
- **references/** — Complete details: full API signatures, end-to-end flows, configuration reference
