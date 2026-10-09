"""The harness must be able to log in as the admin it claims to.

Three separate runs failed with "17/26 suites passed" and a wall of 401s, and
none of the three causes was in the panel - all were in this harness:

  1. RESET_SQL emptied every table EXCEPT `admins`, so the account left over
     from an earlier run kept whatever password that run ended on. Two suites
     legitimately change the password mid-run, so any run interrupted between
     the change and the revert left the harness permanently locked out.
  2. The panel only adopts ZEFIRA_ADMIN_PASSWORD when the admins table is
     EMPTY, so fixing (1) alone was not enough.
  3. CHILD_ENV carried the credential but the `uvicorn` Popen() that launches
     the panel did not pass `env=`, so the server inherited the parent
     environment and never saw it. The suites received CHILD_ENV; the process
     that actually had to accept the password did not.

Every failure looked like nine broken suites. It was one stale credential plus
one missing kwarg. These assertions pin all three links, because each of them
fails silently: the harness still runs, still reports results, just with 401
everywhere.
"""
import io
import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
RUNNER = os.path.join(ROOT, "run_all_tests.py")


def read():
    with io.open(RUNNER, encoding="utf-8-sig", newline="") as fh:
        return fh.read()


def checks(src):
    # 1. the reset clears the admin row
    reset = re.search(r"RESET_SQL\s*=\s*\(([\s\S]*?)\n\)", src)
    reset_sql = reset.group(1) if reset else ""

    # 2+3. the credential reaches the panel process, not just the suites
    env_block = re.search(r"CHILD_ENV\s*=\s*dict\(([\s\S]*?)\n\)", src)
    env_src = env_block.group(1) if env_block else ""
    popen = re.search(r"proc\s*=\s*subprocess\.Popen\(([\s\S]*?)\n\s*\)", src)
    popen_src = popen.group(1) if popen else ""
    # Read the call across its continuation lines: `env=CHILD_ENV` sits on the
    # NEXT line, so a single-line regex reports a false failure.
    suite_call = re.search(r"rc\s*=\s*subprocess\.call\(([\s\S]{0,220}?)\)\s*\n", src)

    return {
        "reset clears the admins table":
            "delete from admins" in reset_sql,
        "CHILD_ENV carries the username": "ZEFIRA_ADMIN_USERNAME=ADMIN" in env_src,
        "CHILD_ENV carries the password": "ZEFIRA_ADMIN_PASSWORD=PASSWORD" in env_src,
        # The one that mattered most and was invisible: the panel process must
        # receive the environment, not only the suite subprocesses.
        "the uvicorn Popen passes env=CHILD_ENV":
            re.search(r"env\s*=\s*CHILD_ENV", popen_src) is not None,
        "the panel is launched by uvicorn (so the check above is pointed at it)":
            "uvicorn" in popen_src,
        "the suite subprocess still gets it":
            suite_call is not None and "env=CHILD_ENV" in suite_call.group(0),
        "ADMIN is defined before CHILD_ENV": src.find("ADMIN =") < src.find("CHILD_ENV = dict"),
        "PASSWORD is defined before CHILD_ENV": src.find("PASSWORD =") < src.find("CHILD_ENV = dict"),
    }


def main():
    src = read()
    base = checks(src)
    failures = []

    print("== 1. all three links are connected ==")
    for name, ok in sorted(base.items()):
        print("   %-46s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            failures.append(name)

    print()
    print("== 2. each can fail: undo it, the guard must go red ==")
    mutations = [
        ("stop clearing admins",
         lambda t: t.replace('"c.execute(\'delete from admins\');"\n    ', ""),
         ["reset clears the admins table"]),
        ("drop env= from the panel Popen",
         lambda t: t.replace("stderr=subprocess.STDOUT,\n        env=CHILD_ENV,\n",
                             "stderr=subprocess.STDOUT,\n"),
         ["the uvicorn Popen passes env=CHILD_ENV"]),
        ("drop the password from CHILD_ENV",
         lambda t: t.replace("    ZEFIRA_ADMIN_PASSWORD=PASSWORD,\n", ""),
         ["CHILD_ENV carries the password"]),
    ]
    for name, mutate, must_go_red in mutations:
        mutated = mutate(src)
        if mutated == src:
            print("   %-36s FAIL (mutation inert - untestable)" % name)
            failures.append(name + ": inert")
            continue
        after = checks(mutated)
        still = [g for g in must_go_red if after[g]]
        if still:
            print("   %-36s FAIL (stayed green: %s)" % (name, ", ".join(still)))
            failures.append(name + ": cannot fail")
        else:
            print("   %-36s ok (goes red: %s)" % (name, ", ".join(must_go_red)))

    print()
    if failures:
        print("FAIL: %d problem(s): %s" % (len(failures), "; ".join(failures)))
        return 1
    print("PASS: the harness can reach its own admin.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())