"""install.sh must never execute its own prose.

The systemd unit is written with an UNQUOTED here-document, because $SERVICE,
$TARGET, $ENV_FILE, $BIND_HOST and $PORT all have to expand inside it. Bash
performs command substitution in an unquoted heredoc body - including on text
that reads like a comment. Three backticks in two comments were intended as
quotation marks, and every install executed them as root:

    line 710        `+`                            -> "+: command not found"
    lines 726-727   `sudo -n systemctl restart
                     zefira`                        -> "Too few arguments."

Both messages were seen on a real Ubuntu 24.04 host during testing, and
reproduced byte-for-byte here before the fix. The substitution also consumed
its own text, so the unit shipped with two half-sentences in its comments.

This suite runs bash for real. Git for Windows ships one, which is what
installer_test.py already uses. It slices the actual heredoc out of install.sh,
writes it to a scratch file, and executes it - so a regression shows up as a
command actually running, not as a regex that matches today.
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
INSTALL = os.path.join(ROOT, "install.sh")
BT = chr(96)
BASH = r"C:\Program Files\Git\bin\bash.exe"


def read():
    with io.open(INSTALL, encoding="utf-8", newline="") as fh:
        return fh.read()


def heredoc_bounds(lines):
    start = next(n for n, l in enumerate(lines) if 'cat > "/etc/systemd/system/' in l)
    end = next(n for n in range(start + 1, len(lines)) if lines[n].strip() == "EOF")
    return start, end


def unit_body(src):
    lines = src.split("\n")
    start, end = heredoc_bounds(lines)
    return lines[start + 1:end], lines[start]


def run_here_doc(src, tmpdir):
    """Execute the real heredoc body and report what the shell actually ran."""
    if not os.path.exists(BASH):
        return None, "no bash at %s" % BASH
    body, opener = unit_body(src)
    # Neutralise anything that would touch the real system; the point is to see
    # which command substitutions fire, not to install a unit.
    scrubbed = []
    for l in body:
        l = l.replace("ExecStart=", "#ExecStart=")
        l = l.replace("ExecStartPre=", "#ExecStartPre=")
        l = l.replace("Environment=", "#Environment=")
        scrubbed.append(l)
    script = os.path.join(tmpdir, "unit.sh")
    out = os.path.join(tmpdir, "fake.service")
    with io.open(script, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("#!/usr/bin/env bash\n")
        fh.write('cat > "%s" <<EOF\n' % out.replace("\\", "/"))
        fh.write("\n".join(scrubbed))
        fh.write("\nEOF\n")
        fh.write('echo "rc=$?"\n')
    posix = script.replace("\\", "/")
    try:
        r = subprocess.run([BASH, posix], capture_output=True, text=True, timeout=60)
    except Exception as exc:
        return None, "bash failed to run: %s" % exc
    return (r.stdout + r.stderr), None


def main():
    failures = []
    src = read()
    lines = src.split("\n")
    start, end = heredoc_bounds(lines)
    opener = lines[start]
    body = "\n".join(lines[start + 1:end])

    print("== 1. the heredoc must stay unquoted, and stay backtick-free ==")
    delim = opener.split("<<")[-1].strip()
    unquoted = not delim[:1] in ("'", '"')
    print("   %-46s %s" % ("delimiter is unquoted (vars must expand)",
                           "ok" if unquoted else "FAIL - quoting would stop $PORT expanding"))
    if not unquoted:
        failures.append("delimiter quoted")

    bt = [(n, lines[n].count(BT)) for n in range(start, end + 1) if BT in lines[n]]
    print("   %-46s %s" % ("no backticks anywhere in the unit body",
                           "ok" if not bt else "FAIL at lines %s" % [n for n, _ in bt]))
    if bt:
        failures.append("backticks in the unit body")

    print()
    print("== 2. the shell really does execute it: run the actual heredoc ==")
    tmp = tempfile.mkdtemp(prefix="zefira_unit_")
    try:
        combined, err = run_here_doc(src, tmp)
        if combined is None:
            print("   SKIPPED: %s" % err)
            print("   -> the static checks above still ran and still apply.")
        else:
            executed = ("command not found" in combined
                        or "Too few arguments" in combined
                        or "unexpected argument" in combined
                        or "Usage:" in combined)
            print("   %-46s %s" % ("executing install.sh's unit body runs nothing",
                                   "FAIL - the shell executed the prose" if executed else "ok"))
            if executed:
                failures.append("unit body still executes")
                for l in combined.splitlines()[:6]:
                    print("      %s" % l[:96])
            else:
                for l in combined.splitlines()[:3]:
                    if l.strip():
                        print("      %s" % l[:96])
            # And the comments must survive into the written file intact.
            fake = os.path.join(tmp, "fake.service")
            if os.path.exists(fake):
                with io.open(fake, encoding="utf-8", errors="replace") as fh:
                    written = fh.read()
                intact = ("'+'" in written and "'sudo -n systemctl restart" in written)
                print("   %-46s %s" % ("the prose lands in the unit file intact",
                                       "ok" if intact else "FAIL - substitution ate the text"))
                if not intact:
                    failures.append("unit comments mangled")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("== 3. the guard can fail: put the backticks back ==")
    mutated = src.replace("'+'", "`+`", 1)
    if mutated == src:
        print("   %-46s FAIL (mutation inert)" % "reintroduce `+`")
        failures.append("mutation inert")
    else:
        tmp2 = tempfile.mkdtemp(prefix="zefira_unit_mut_")
        try:
            combined, err = run_here_doc(mutated, tmp2)
            if combined is None:
                print("   %-46s SKIPPED (no bash)" % "reintroduce `+`")
            else:
                bad = ("command not found" in combined or "Too few arguments" in combined
                       or "unexpected argument" in combined or "Usage:" in combined)
                if bad:
                    print("   %-46s ok (goes red: the prose executes)" % "reintroduce `+`")
                    for l in combined.splitlines()[:3]:
                        if l.strip():
                            print("      %s" % l[:96])
                else:
                    print("   %-46s FAIL - the old bug does not reproduce" % "reintroduce `+`")
                    failures.append("guard cannot fail")
        finally:
            shutil.rmtree(tmp2, ignore_errors=True)

    print()
    if failures:
        print("FAIL: %d problem(s): %s" % (len(failures), "; ".join(failures)))
        return 1
    print("PASS: install.sh no longer executes its own comments.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())