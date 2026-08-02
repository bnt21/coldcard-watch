#!/usr/bin/env python3
"""
check-clean.py — refuse to commit anything that would expose a machine or a credential.

Everything in this tree is meant to be readable by strangers eventually, so the things
that must never be in it are: the address of anybody's node, a Keychain service name, a
home directory path, a credential of any kind, and the deployment linkage that ties the
repo to one hosting account.

Runs over exactly what git would track, so a pattern hiding in an ignored working file
cannot fail the build and a newly-tracked file cannot sneak past.

Exit 0 clean, 1 dirty. Wire it as a pre-commit hook, and run it before any push.

usage: check-clean.py [--staged]
"""
import re
import subprocess
import sys

# Each rule is (label, regex). Keep them narrow enough to mean something when they fire.
RULES = [
    ("node hostname (.onion or .local)", re.compile(r'\b[a-z2-7]{16,}\.(onion|local)\b')),
    ("private LAN address", re.compile(r'\b(?:192\.168|10\.(?:\d{1,3})|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b')),
    ("keychain service name, inline literal", re.compile(r'find-generic-password[^\n]*?-s"?,\s*"[\w\-]+"')),
    ("home directory path", re.compile(r'/(?:Users|home)/(?!<)[a-z][\w\-]*')),
    ("bearer/api token value", re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9\-]{10,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b')),
    ("private key block", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY')),
    ("vercel project linkage", re.compile(r'"(?:orgId|projectId)"\s*:')),
]

# Places a pattern is legitimately allowed to appear: documentation of the pattern itself.
ALLOW = {
    "check-clean.py",          # this file is nothing but the patterns
    "nodeconf.py",             # documents the env var names, holds no address
    "README.md",               # shows an example config with a placeholder address
}


def tracked(staged):
    cmd = (["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"] if staged
           else ["git", "ls-files"])
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    return [f for f in out.splitlines() if f.strip()]


def main():
    staged = "--staged" in sys.argv
    files = tracked(staged)
    if not files:
        print("nothing to check")
        return 0

    bad = 0
    for f in files:
        if f in ALLOW:
            continue
        try:
            s = open(f, encoding="utf-8", errors="replace").read()
        except (IsADirectoryError, FileNotFoundError):
            continue
        for label, pat in RULES:
            for m in pat.finditer(s):
                line = s[:m.start()].count("\n") + 1
                # report the finding, never the matched value
                print(f"  LEAK  {f}:{line}  {label}")
                bad += 1

    print(f"\nchecked {len(files)} tracked files")
    if bad:
        print(f"{bad} finding(s). Nothing is committed until the tree is clean.")
        return 1
    print("clean: no node address, credential, home path, or deploy linkage")
    return 0


if __name__ == "__main__":
    sys.exit(main())
