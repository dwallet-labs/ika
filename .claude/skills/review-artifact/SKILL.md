---
name: review-artifact
description: Publish a markdown review, audit or code walkthrough as a claude.ai artifact page the reviewer can comment on, in the fixed house shell (serif body, sticky contents list, code and table wrappers, light and dark themes). Use whenever a review document, audit list, or walkthrough in a repo's dev-docs is to be published or republished as an artifact, in any repo.
---

# Publishing a review document as an artifact

The reviewer reads and comments on review documents as claude.ai
artifacts, not in the repo. Every such page uses one shell, so the
reviewer sees the same layout each time: a masthead (eyebrow, title,
one-sentence subtitle, a meta line with the file path, branch and base
commit), a sticky contents list on wide screens, serif body text, code
and table wrappers that scroll sideways, native mermaid diagrams, and a
light and a dark palette. Do not design a new page; render the markdown
into this shell.

## The three rules

1. **The markdown in the repo is the source.** The page is generated
   from it and never edited by hand. An answer to a reviewer's comment
   goes into the markdown, then the page is regenerated and republished
   to the same URL, and the comment thread gets a pointer to the section.
   Never resolve a thread.
2. **The meta line names the file, the branch and the base commit**, so
   every `file:line` in the page can be checked against one commit.
   Regenerate the page whenever the base commit changes.
3. **One artifact per document, kept for its life.** Republish to the
   same URL (same file path in the same session, or `url:` from another
   session). Never create a second artifact for a document that has one.

## How to render

```bash
SKILL=.claude/skills/review-artifact
python3 -m pip install markdown   # once per machine, or use a venv
$SKILL/render_page.py dev-docs/reviews/<doc>.md /path/to/scratch/<doc>.html \
  --title "Short Name" \
  --h1 "The full heading of the document" \
  --sub "One sentence: what the page holds and for whom." \
  --meta "dev-docs/reviews/<doc>.md &middot; branch <branch> &middot; base <commit> (<date>)" \
  --eyebrow "<project> &middot; dev-docs review"
```

- `--title` is the tab and gallery name: two to four words, a name,
  no explainer after a colon or dash.
- `--toc-depth 3` lists `###` headings in the contents; the default 2
  lists only `##`. Use 2 when every section repeats the same `###`
  names (Unrequested, Already filed, …), 3 for a walkthrough whose
  `###` headings are the flows.
- Mermaid blocks (```mermaid fences) render natively in the artifact
  viewer. Run the repo's mermaid check first if it has one.
- Write the rendered file in the session scratchpad, not in the repo.

Then publish with the Artifact tool: `file_path` = the rendered file,
`icon` = one generic word on the first publish only (`checklist` for an
audit, `book` for a walkthrough), `description` = one sentence for the
gallery card. On a republish pass the same file path (or the artifact's
`url`) and omit `icon`.

## Before publishing

- Every citation in the markdown is `path:line` or `path:A-B` in
  backticks, relative to the repo root, at the base commit named in the
  meta line, verified by printing the lines. A checker that resolves
  every citation and fails on a missing file or an out-of-range line
  belongs beside the document (`check_cites.py` in this skill is a
  starting point; copy it into the repo's scripts if the repo has none).
- The document follows the repo's communication rules (plain words, one
  idea per sentence, the actor named in every sentence).
- The document is committed on the review branch before the page is
  published, so the page and the repo agree.

## Files in this skill

- `shell.html`: the page shell with `{{TITLE}}`, `{{EYEBROW}}`,
  `{{H1}}`, `{{SUB}}`, `{{META}}`, `{{TOC}}`, `{{BODY}}` placeholders.
  Change it only when the reviewer asks for a layout change; the change
  then applies to every page on the next regeneration.
- `render_page.py`: the renderer.
- `check_cites.py`: verifies every `path:line` citation in a markdown
  file against a checkout root (`ROOT` env var or first argument).
