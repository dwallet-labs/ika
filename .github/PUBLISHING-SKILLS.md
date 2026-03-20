# Publishing Skills to ClawHub

## Prerequisites

- `CLAWHUB_TOKEN` secret configured in GitHub repository settings

## Release Publish (via tag)

1. Update `version:` in `skills/<skill-name>/SKILL.md` (e.g., `version: 1.1.0`)
2. Commit and push to `main`
3. Create and push a tag:
   ```bash
   git tag skills/<skill-name>-<version>
   # Example:
   git tag skills/ika-sdk-1.1.0
   git push origin skills/ika-sdk-1.1.0
   ```
4. The workflow validates that the tag version matches the `version:` field in `SKILL.md`
5. Only the skill named in the tag is published

### Tag format

```
skills/{skill_name}-{version}
```

Examples:
- `skills/ika-sdk-1.1.0`
- `skills/ika-cli-2.0.0`
- `skills/ika-move-1.0.1`

## Pre-release Publish (manual dispatch)

For testing a skill version before a formal release:

1. Go to **Actions** > **Publish Skills to ClawHub** > **Run workflow**
2. Fill in:
   - **Skill**: folder name (e.g., `ika-sdk`) or `all` for all skills
   - **Version**: must include a pre-release tag (e.g., `1.1.0-beta`, `1.0.0-rc1`)
3. Click **Run workflow**

Bare versions like `1.1.0` are rejected on manual dispatch — they are reserved for tag-based releases.

## What happens

- **Tag push**: Parses skill name and version from the tag, validates against `SKILL.md`, publishes that single skill
- **Manual dispatch**: Overrides the version in `SKILL.md` at build time, publishes the selected skill(s) with the pre-release version

## Available skills

| Skill | Directory |
|-------|-----------|
| ika-cli | `skills/ika-cli/` |
| ika-sdk | `skills/ika-sdk/` |
| ika-move | `skills/ika-move/` |
| ika-operator | `skills/ika-operator/` |
