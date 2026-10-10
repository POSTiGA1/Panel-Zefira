"""Report which releases the public docs never mention.

The public assistant answered "what is new?" with v1.13.3 while the panel was
on v1.15.23, and docs/changelog.html stopped at v1.15.2. Twenty-one releases
shipped with no public entry at all - including the updater-guard bypass and
the root escalation in install.sh - so their only record was a commit subject
nobody outside the repository could read.

This script does NOT write the entries. The changelog is translated prose in
four languages, and a generated entry would be neither accurate nor
translatable. What it does is make the gap impossible to overlook: it lists
every tag with no entry, and quotes the commit subject that describes each one,
so writing them is a mechanical copy rather than a research task.

It also checks the assistant's own "what is new" entry, because a visitor
asking that question gets a confident answer from a stale list.

Run after tagging a release:
    .venv\\Scripts\\python docs/release_notes.py
"""
import io
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHANGELOG = os.path.join(ROOT, "docs", "changelog.html")
KNOWLEDGE = os.path.join(ROOT, "docs", "assets", "site-knowledge.json")


def git(*args):
    return subprocess.run(["git"] + list(args), cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8").stdout


def tags():
    out = git("tag", "--list", "v*", "--sort=-v:refname")
    return [t.strip() for t in out.splitlines() if re.match(r"^v\d+\.\d+\.\d+$", t.strip())]


def subject(tag, ordered):
    """The commit subject describing this release.

    The release commit names the version it PRODUCES, so `v1.15.22..v1.15.23`
    yields "v1.15.23: ...". That means the subject for a tag is found in the
    range that ENDS at the next tag, not the one that starts at it. Looking at
    `tag..next` returned the next release's title, and looking at
    `prev..tag` returned whatever the preceding commit happened to be named -
    which is why the first version of this reported "no subject found" for
    twenty of twenty-one tags.
    """
    idx = ordered.index(tag)
    if idx + 1 < len(ordered):
        out = git("log", "--no-merges", "--pretty=format:%s",
                  "%s..%s" % (tag, ordered[idx + 1]))
    else:
        out = git("log", "--no-merges", "--pretty=format:%s", "-1", tag)
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    for l in lines:
        if tag in l:
            return re.sub(r"^v\d+\.\d+\.\d+:\s*", "", l).rstrip(".")
    return lines[0] if lines else None


def how_many_behind(newest_seen, current):
    """How many releases the visitor is not being told about."""
    return max(0, len([t for t in tags() if t <= current and t > newest_seen]))


def main():
    t = tags()
    if not t:
        print("no version tags found; run from inside the repository")
        return 1
    ordered = t[::-1]

    ch = io.open(CHANGELOG, encoding="utf-8").read()
    present = set(re.findall(r'<h2 id="v(\d+)">', ch))
    missing = [(tag, subject(tag, ordered)) for tag in t
               if tag[1:].replace(".", "") not in present]

    print("%d release tags; changelog.html documents %d of them" % (len(t), len(t) - len(missing)))
    print()
    if missing:
        print("UNDOCUMENTED (%d), newest first. Each line is the commit subject that" % len(missing))
        print("describes it - use them as the entry text:\n")
        for tag, s in missing:
            print("  %-9s %s" % (tag, s or "(no subject found)"))
    else:
        print("changelog.html documents every tag.")

    kb = json.load(io.open(KNOWLEDGE, encoding="utf-8"))
    ent = next((e for e in kb if e.get("id") == "changelog"), None)
    print()
    if ent:
        vers = re.findall(r"v(\d+\.\d+\.\d+)", ent.get("text", ""))
        newest_seen = "v" + vers[0] if vers else "v0.0.0"
        newest = newest_seen
        cur = "v" + io.open(os.path.join(ROOT, "VERSION"), encoding="utf-8").read().strip()
        print("assistant 'what is new' entry mentions up to : %s" % newest)
        print("repository VERSION                           : %s" % cur)
        if newest != cur:
            behind = how_many_behind(newest_seen, cur)
            print("  -> STALE: the list stops at %s, the panel ships %s." % (newest, cur))
            print("     %d release(s) are not in it. A visitor asking what is new"
                  % behind)
            print("     gets a confident answer from a list this old. Update the")
            print("     `changelog` entry's text in docs/assets/site-knowledge.json")
            print("     in all four locales (text, fa, zh, ru).")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())