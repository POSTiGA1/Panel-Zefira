"""The `bot` token scope must be reachable from the panel.

`schemas.py` declares `scopes: Literal["full", "bot"] = "full"` and the API
docs tell the operator to create a long-lived token "under Settings -> API
Tokens with scope full (default, everything) or bot (least-privilege for
resellers)". But the panel's create form had only a name field: it posted
`{name, password_confirm}` and never sent `scopes`, so the schema default
applied to every token and the documented `bot` scope was unreachable from
the UI. Every token an operator could mint was therefore a `full` credential
able to delete users, restore backups and change settings.

This suite pins the control in place. Each assertion is checked against a
MUTATED COPY of the real files, not just the pristine ones: a guard that
cannot go red is worse than no guard, so every mutation below must turn a
named assertion off.
"""
import io
import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(ROOT, "templates", "panel.html")
APPJS = os.path.join(ROOT, "static", "app.js")
I18N = os.path.join(ROOT, "static", "i18n.js")
SCHEMAS = os.path.join(ROOT, "schemas.py")

LOCALES = ("Token name", "نام توکن", "令牌名称", "Имя токена")
SCOPE_KEYS = ("tokens.scopeLabel", "tokens.scopeFull", "tokens.scopeBot")

# The exact run of text each locale now carries after `tokens.nameLabel`.
# Matched literally on purpose: a regex over these strings is unreliable,
# because the Russian and Farsi values contain parentheses.
SCOPE_RUNS = {
    "Token name": '"tokens.scopeLabel": "Scope", "tokens.scopeFull": "Full (everything)", "tokens.scopeBot": "Bot (least privilege)", ',
    "نام توکن": '"tokens.scopeLabel": "سطح دسترسی", "tokens.scopeFull": "کامل (همه‌چیز)", "tokens.scopeBot": "ربات (کمترین دسترسی)", ',
    "令牌名称": '"tokens.scopeLabel": "权限范围", "tokens.scopeFull": "完整（全部）", "tokens.scopeBot": "机器人（最小权限）", ',
    "Имя токена": '"tokens.scopeLabel": "Область", "tokens.scopeFull": "Полная (всё)", "tokens.scopeBot": "Бот (минимум прав)", ',
}


def read(path):
    with io.open(path, encoding="utf-8-sig", newline="") as fh:
        return fh.read()


def checks(panel, appjs, i18n):
    """Every assertion this suite makes, as a dict of name -> bool."""
    return {
        "panel renders a scope control":
            'id="apitoken-scope"' in panel,
        "control offers exactly full and bot":
            panel.count('value="full"') >= 1 and panel.count('value="bot"') >= 1
            and panel.count('data-i18n="tokens.scopeFull"') == 1
            and panel.count('data-i18n="tokens.scopeBot"') == 1,
        "control sits in the token card":
            panel.find("apitoken-scope") > panel.find("apitoken-name"),
        "create request carries the scope":
            "scopes: scope" in appjs,
        "client refuses an unknown scope":
            re.search(r'scopeSel\.value === "bot"\s*\|\|\s*scopeSel\.value === "full"', appjs) is not None,
        "absent control falls back to full":
            re.search(r'\?\s*scopeSel\.value\s*:\s*"full"', appjs) is not None,
        "one create call only":
            appjs.count('api("/api/api-tokens", { method: "POST"') == 1,
        "all four locales translate the control":
            all(run in i18n for run in SCOPE_RUNS.values()),
    }


def main():
    panel, appjs, i18n = read(PANEL), read(APPJS), read(I18N)
    schemas = read(SCHEMAS)
    base = checks(panel, appjs, i18n)
    failures = []

    print("== 1. the control is present and the scope is sent ==")
    for name, ok in sorted(base.items()):
        print("   %-38s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            failures.append(name)

    print()
    print("== 2. the server still accepts the field (this suite must not drift from the schema) ==")
    declared = re.search(r'scopes:\s*Literal\[\s*"full"\s*,\s*"bot"\s*\]\s*=\s*"full"', schemas)
    print("   schemas.py ApiTokenCreateIn scopes field   %s" % ("ok" if declared else "FAIL"))
    if not declared:
        failures.append("schema no longer declares scopes")

    print()
    print("== 3. every assertion can fail: remove the fix, the guard must go red ==")
    mutations = [
        ("drop the scope control", PANEL,
         lambda t: re.sub(r'\s*<label class="field"><span data-i18n="tokens\.scopeLabel">.*?</select></label>', "", t, flags=re.S),
         ["panel renders a scope control", "control offers exactly full and bot"]),
        ("drop the bot option", PANEL,
         lambda t: t.replace('<option value="bot" data-i18n="tokens.scopeBot">Bot (least privilege)</option>', ""),
         ["control offers exactly full and bot"]),
        ("stop sending scopes", APPJS,
         lambda t: t.replace("scopes: scope", "scopes: undefined"),
         ["create request carries the scope"]),
        ("trust the select blindly", APPJS,
         lambda t: re.sub(r'const scope = \(scopeSel.*?;', 'const scope = scopeSel.value;', t, flags=re.S),
         ["client refuses an unknown scope"]),
        ("strip the ru translation", I18N,
         lambda t: t.replace(SCOPE_RUNS["Имя токена"], ""),
         ["all four locales translate the control"]),
    ]
    for name, path, mutate, must_go_red in mutations:
        source = {"panel": panel, "appjs": appjs, "i18n": i18n}
        key = {PANEL: "panel", APPJS: "appjs", I18N: "i18n"}[path]
        mutated = mutate(source[key])
        if mutated == source[key]:
            print("   %-26s FAIL (mutation did not apply - this guard is untestable)" % name)
            failures.append(name + ": mutation inert")
            continue
        source[key] = mutated
        after = checks(source["panel"], source["appjs"], source["i18n"])
        still_green = [g for g in must_go_red if after[g]]
        if still_green:
            print("   %-26s FAIL (stayed green: %s)" % (name, ", ".join(still_green)))
            failures.append(name + ": guard cannot fail")
        else:
            print("   %-26s ok (goes red: %s)" % (name, ", ".join(must_go_red)))

    print()
    print("== 4. every audit event the panel emits has a label in all four locales ==")
    # app.js renders an audit row with `eventName(ev)`, which returns the raw
    # constant when `t("event." + ev)` is missing (`v === k ? ev : v`). So an
    # event with no key is shown to the operator as `USERS_LIST` or `PW_FAIL`.
    # main.py is the source of truth for what can actually be logged.
    mainpy = read(os.path.join(ROOT, "main.py"))
    emitted = sorted(set(re.findall(r'audit\(\s*s?\b[^,]*,\s*"([A-Z_]{3,})"', mainpy)))
    emitted = [e for e in emitted if not e.startswith("APITOKEN") or e in
               ("APITOKEN_CREATE", "APITOKEN_DELETE", "APITOKEN_FAIL", "APITOKEN_SELFTEST")]
    spans = {}
    for m in re.finditer(r'Object\.assign\(Z_STRINGS\.(en|fa|zh|ru),\s*\{', i18n):
        start = m.end()
        depth, i = 1, start
        while i < len(i18n) and depth:
            if i18n[i] == "{":
                depth += 1
            elif i18n[i] == "}":
                depth -= 1
            i += 1
        spans.setdefault(m.group(1), []).append((m.start(), i))
    print("   events emitted by main.py: %d" % len(emitted))
    for loc in ("en", "fa", "zh", "ru"):
        have = set()
        for a, b in spans.get(loc, []):
            have |= set(re.findall(r'"event\.(\w+)"', i18n[a:b]))
        missing = [e for e in emitted if e not in have]
        print("   %-3s %d/%d labelled %s" % (loc, len(emitted) - len(missing), len(emitted),
                                              "" if not missing else "MISSING " + ", ".join(missing)))
        if missing:
            failures.append("audit events unlabelled in " + loc)

    print()
    print("== 5. the audit guard can fail too: drop a label, it must go red ==")
    victim = re.search(r'"event\.USERS_LIST":\s*"[^"]*",\s*', i18n)
    if not victim:
        # Already unlabelled - that is section 4's finding, and there is nothing
        # left to remove. Report it instead of raising AttributeError, which
        # would hide the real cause behind a stack trace.
        print("   dropping the USERS_LIST label    n/a (no such label exists yet)")
        failures.append("audit label for USERS_LIST is absent")
    else:
        after = i18n.replace(victim.group(0), "", 1)
        gone = [loc for loc, blocks in spans.items()
                if any('"event.USERS_LIST"' not in after[a:b] for a, b in blocks)]
        print("   dropping the USERS_LIST label    %s" % ("ok (goes red in: %s)" % ", ".join(sorted(gone)) if gone else "FAIL - stayed green"))
        if not gone:
            failures.append("audit guard cannot fail")

    print()
    if failures:
        print("FAIL: %d problem(s): %s" % (len(failures), "; ".join(failures)))
        return 1
    print("PASS: the bot scope is reachable, and every guard above can fail.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())