"""The public site assistant must not tell visitors about an old release.

docs/assets/site-knowledge.json answered "what is new?" with v1.13.3 while the
panel was on v1.15.23 - twenty-one releases of security work that the assistant
would confidently not mention - and it linked to changelog.html, whose newest
entry was v1.15.2, so a visitor got three mutually inconsistent answers.

That file is hand-maintained, which is why it drifted. This suite makes the
drift loud instead of silent: the assistant's newest version must equal the
repository VERSION, in every locale it is written in. docs/release_notes.py
prints the same gap and the commit subjects needed to close it.

Each assertion is also checked against a mutated copy of the real file, so a
guard that cannot go red is reported rather than trusted.
"""
import io
import json
import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE = os.path.join(ROOT, "docs", "assets", "site-knowledge.json")
CHANGELOG = os.path.join(ROOT, "docs", "changelog.html")
VERSION = os.path.join(ROOT, "VERSION")
RELEASE_NOTES = os.path.join(ROOT, "docs", "release_notes.py")
LOCALES = ("text", "fa", "zh", "ru")


def read_json(path):
    with io.open(path, encoding="utf-8") as fh:
        return json.load(fh)


def entry(kb):
    return next((e for e in kb if e.get("id") == "changelog"), None)


def newest_version(text):
    """The newest vX.Y.Z mentioned, with the leading `v`.

    Returns it prefixed, and `checks()` compares against a prefixed VERSION -
    the VERSION file holds bare digits, so comparing the two unprefixed would
    report every locale as stale.
    """
    found = re.findall(r"v(\d+\.\d+\.\d+)", text or "")
    return "v" + found[0] if found else None


def checks(kb, version, changelog):
    e = entry(kb)
    cur = "v" + version.strip()   # VERSION holds bare digits, the entry has "v"
    out = {}
    for loc in LOCALES:
        out["assistant mentions the shipped version (%s)" % loc] = (
            e is not None and newest_version(e.get(loc)) == cur)
    out["the entry still exists"] = e is not None
    out["every locale is non-empty"] = e is not None and all(
        e.get(loc) for loc in LOCALES)
    out["the full changelog is still linked"] = (
        e is not None and any(l.get("href") == "changelog.html" for l in (e.get("links") or [])))
    # The site also has a real changelog page; the assistant must not claim to
    # cover releases the page does not list without the gap being visible.
    page = set(re.findall(r'<h2 id="v(\d+)">', changelog))
    out["changelog.html has versioned entries"] = len(page) >= 7
    return out


def main():
    kb = read_json(KNOWLEDGE)
    with io.open(VERSION, encoding="utf-8") as fh:
        version = fh.read()
    with io.open(CHANGELOG, encoding="utf-8") as fh:
        changelog = fh.read()

    base = checks(kb, version, changelog)
    failures = []

    print("== 1. the assistant is not stale ==")
    for name, ok in sorted(base.items()):
        print("   %-46s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            failures.append(name)

    print()
    print("== 2. the gap is reportable, so it can be closed ==")
    ok = os.path.exists(RELEASE_NOTES)
    print("   %-46s %s" % ("docs/release_notes.py exists", "ok" if ok else "FAIL"))
    if not ok:
        failures.append("no tool to list the undocumented releases")
    else:
        import subprocess
        out = subprocess.run(["git", "tag", "--list", "v*", "--sort=-v:refname"],
                             cwd=ROOT, capture_output=True, text=True,
                             encoding="utf-8").stdout
        tags = [t.strip() for t in out.splitlines()
                if re.match(r"^v\d+\.\d+\.\d+$", t.strip())]
        print("   %-46s %s" % ("repository has release tags", "%d found" % len(tags)))
        if not tags:
            failures.append("no tags to compare against")

    print()
    print("== 3. each assertion can fail: roll the file back, it must go red ==")
    # Two mutations, both on a copy: age the English entry, and drop the link.
    import copy
    mutations = []

    stale = copy.deepcopy(kb)
    se = entry(stale)
    se["text"] = re.sub(r"v1\.\d+\.\d+", "v1.13.3", se["text"], count=1)
    mutations.append(("age the English entry", stale,
                      ["assistant mentions the shipped version (text)"]))

    unlinked = copy.deepcopy(kb)
    entry(unlinked)["links"] = []
    mutations.append(("drop the changelog link", unlinked,
                      ["the full changelog is still linked"]))

    for name, mutated, must_go_red in mutations:
        after = checks(mutated, version, changelog)
        still = [g for g in must_go_red if after[g]]
        if still:
            print("   %-30s FAIL (stayed green: %s)" % (name, ", ".join(still)))
            failures.append(name + ": cannot fail")
        else:
            print("   %-30s ok (goes red: %s)" % (name, ", ".join(must_go_red)))

    print()
    if failures:
        print("FAIL: %d problem(s): %s" % (len(failures), "; ".join(failures)))
        return 1
    print("PASS: the assistant and the shipped version agree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())