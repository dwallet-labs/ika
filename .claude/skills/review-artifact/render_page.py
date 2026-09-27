#!/usr/bin/env python3
"""Render a markdown review or walkthrough into the artifact page shell.

usage:
  render_page.py <doc.md> <out.html> --title "Short Name" --h1 "Full heading" \
      --sub "One-sentence subtitle" --meta "path/in/repo.md · branch X · base abc123 (YYYY-MM-DD)" \
      [--eyebrow "project · dev-docs review"] [--toc-depth 2|3]

Needs the `markdown` package: python3 -m pip install markdown
(or a venv: python3 -m venv .venv && .venv/bin/pip install markdown).
The markdown's first-line H1 is dropped; the masthead carries the title.
"""
import argparse, html, os, re, sys

try:
    import markdown
except ImportError:
    sys.exit("missing module: run `python3 -m pip install markdown` (or use a venv) and retry")

ap = argparse.ArgumentParser()
ap.add_argument("md"); ap.add_argument("out")
ap.add_argument("--title", required=True); ap.add_argument("--h1", required=True)
ap.add_argument("--sub", required=True); ap.add_argument("--meta", required=True)
ap.add_argument("--eyebrow", default="dev-docs review")
ap.add_argument("--toc-depth", type=int, default=2, choices=(2, 3))
a = ap.parse_args()

shell = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "shell.html")).read()
src = open(a.md).read().split("\n")
if src and src[0].startswith("# "):
    src = src[1:]
body = markdown.markdown("\n".join(src), extensions=["fenced_code", "tables"])

def slug(text):
    text = html.unescape(re.sub(r"<[^>]+>", "", text)).lower()
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-")

toc = []
def heading(m):
    level, inner = m.group(1), m.group(2)
    sid = slug(inner)
    if int(level) <= a.toc_depth:
        toc.append(f'<a class="toc-{level}" href="#{sid}">{inner}</a>')
    return f'<h{level} id="{sid}">{inner}</h{level}>'
body = re.sub(r"<h([234])>(.*?)</h\1>", heading, body, flags=re.S)
body = re.sub(r'<pre><code class="language-mermaid">(.*?)</code></pre>',
              lambda m: '<div class="diagram"><pre class="mermaid">' + m.group(1) + "</pre></div>", body, flags=re.S)
body = re.sub(r"<pre><code([^>]*)>(.*?)</code></pre>", r'<div class="code-wrap"><pre><code\1>\2</code></pre></div>', body, flags=re.S)
body = body.replace("<table>", '<div class="table-wrap"><table>').replace("</table>", "</table></div>")
nav = '<nav class="toc" aria-label="Contents">\n<p class="toc-head">Contents</p>\n' + "\n".join(toc) + "\n</nav>"

page = shell
for k, v in {"TITLE": a.title, "H1": a.h1, "SUB": a.sub, "META": a.meta, "EYEBROW": a.eyebrow, "TOC": nav, "BODY": body}.items():
    page = page.replace("{{" + k + "}}", v)
open(a.out, "w").write(page)
print(f"wrote {a.out}: {len(page)} bytes, {len(toc)} toc entries, {body.count('class=\"mermaid\"')} diagrams")
