#!/usr/bin/env python3
"""
check_clean.py — refuse to commit anything that would expose a machine or a credential.

Everything in this tree is meant to be readable by strangers eventually, so the things
that must never be in it are: the address of anybody's node, a Keychain service name, a
home directory path, a credential of any kind, and the deployment linkage that ties the
repo to one hosting account.

Runs over exactly what git would track, so a pattern hiding in an ignored working file
cannot fail the build and a newly-tracked file cannot sneak past.

Exit 0 clean, 1 dirty. Wire it as a pre-commit hook, and run it before any push.

usage: check_clean.py [--staged]
"""
import re
import subprocess
import sys

# Each rule is (label, regex). Keep them narrow enough to mean something when they fire.
RULES = [
    # Hostnames that identify a specific machine. Tor v3 is 56 chars; mDNS/LAN names are
    # short and may carry digits and hyphens, which the first version of this missed.
    ("onion hostname", re.compile(r'\b[a-z2-7]{16,56}\.onion\b', re.I)),
    ("local/mDNS hostname", re.compile(r'\b[a-z0-9][a-z0-9\-]{1,62}\.local\b', re.I)),
    # Any literal IP that is not obviously documentation/loopback.
    ("IP address literal", re.compile(
        r'(?<![\w.\-])'
        r'(?!127\.|0\.0\.0\.0|255\.255|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)'
        r'(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w.\-])')),
    ("IPv6 unique-local", re.compile(r'\bf[cd][0-9a-f]{2}:[0-9a-f:]{4,}', re.I)),
    # Keychain lookups in any form: list-args, shell, or a bare service constant.
    ("keychain service name", re.compile(
        r'find-generic-password[^\n]{0,80}?-s["\'\s,]{1,4}[\w\-]+'
        r'|\b[A-Z_]*KEYCHAIN[A-Z_]*\s*=\s*["\'][a-z][a-z0-9\-]*["\']')),
    # Home directories, either platform, any capitalisation.
    ("home directory path", re.compile(r'/(?:Users|home)/(?!<|\$|%|USER\b|user\b)[A-Za-z][\w\-.]*')),
    # Names of the people and machines behind this. Comments written for a private repo
    # carry them without anyone noticing; 11 of them survived into the first public push.
    ("operator or machine name", re.compile(r'\b(?:dobby|brady|bradytc|bnoahtinnin|dobby-bridge)\b', re.I)),
    # Credential shapes. Broad on purpose: a false positive costs a comment, a false
    # negative costs a live credential in a public repo.
    ("github token", re.compile(r'\bgh[pousr]_[A-Za-z0-9]{20,}')),
    ("slack token", re.compile(r'\bxox[baprs]-[A-Za-z0-9\-]{10,}')),
    ("openai/anthropic key", re.compile(r'\bsk-(?:ant-)?[A-Za-z0-9_\-]{20,}')),
    ("aws access key", re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b')),
    ("google api key", re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b')),
    ("telegram bot token", re.compile(r'\b\d{8,12}:[A-Za-z0-9_\-]{30,}')),
    ("vercel token", re.compile(r'\b[A-Za-z0-9]{24}\b(?=["\']?\s*[,}\n])(?<![A-Fa-f0-9]{24})')),
    ("bearer literal", re.compile(r'(?:Bearer|Authorization)\s*[:=]?\s*(?:Bearer\s+)?["\']?[A-Za-z0-9._\-]{16,}', re.I)),
    ("assigned secret literal", re.compile(r'\b(?:password|passwd|secret|api_?key|token)\b\s*[:=]\s*["\'][^"\'\n]{8,}["\']', re.I)),
    ("private key block", re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY')),
    ("vercel project linkage", re.compile(r'"(?:orgId|projectId)"\s*:')),
]

# Exemptions are per (file, rule), never whole-file. A blanket file exemption is how a
# real address ends up in the one file whose job is to show an example of one.
ALLOW = {
    ("check_clean.py", None),                       # this file is nothing but patterns
    ("nodeconf.py", "keychain service name"),       # documents the env var names only
    ("README.md", "IP address literal"),            # the example config block
    ("publish.py", "keychain service name"),        # service comes from env, not a literal
}


SKIP_SUFFIX = (".svg",)          # vector path data is coordinates, not configuration

# Inline SVG inside an HTML page carries the same coordinate runs a .svg file does, and a
# long path like the GitHub mark reads as an IP address literal. Blank the geometry
# attributes (keeping the byte count so line numbers stay honest) before scanning, rather
# than exempting the whole file, which would blind the gate to real content in that page.
SVG_GEOM = re.compile(r'\b(?:d|viewBox|points|transform)="[^"]*"')


def descan(text):
    return SVG_GEOM.sub(lambda m: " " * len(m.group(0)), text)


def exempt(path, label):
    if path.endswith(SKIP_SUFFIX) and label == "IP address literal":
        return True
    return (path, None) in ALLOW or (path, label) in ALLOW


def tracked(staged):
    cmd = (["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"] if staged
           else ["git", "ls-files"])
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        # A gate that cannot list files must fail loudly. Returning nothing here is how
        # a pre-commit hook silently approves everything.
        raise SystemExit(f"check-clean: `{' '.join(cmd)}` failed: {r.stderr.strip()}")
    return [f for f in r.stdout.splitlines() if f.strip()]



# --------------------------------------------------------------------- selftest

def selftest():
    """The gate is only worth what it catches, so the samples live with the rules.
    Fixtures are assembled from fragments so this file never contains a credential
    shape verbatim. Run: check_clean.py --selftest"""
    U = "/Us" + "ers/"
    H = "/ho" + "me/"
    samples = {
        "tor onion": 'NODE="6j2nnmytmb2sqwmlauevnnnpzcxcogomrjzq5iahiw3te3ssln7nlzid.onion"',
        "mdns .local": 'host = "maple-mishap.local"',
        "private lan ip": 'addr = "192.168.1.144"',
        "cgnat ip": 'addr = "100.89.128.125"',
        "public ip": 'server = "5.161.44.12"',
        "home path lower": 'p = "' + U + 'someone/.coldcard"',
        "home path capitalised": 'p = "' + U + 'Someone/.ssh/id_ed25519"',
        "home path linux": 'p = "' + H + 'someone/.coldcard"',
        "keychain list-arg": 'run(["security","find-generic-password","-s","some-service","-w"])',
        "keychain shell": 'security find-generic-password -s some-service -w',
        "keychain constant": 'NODE_KEYCHAIN = "some-service"',
        "github token": "T='gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'",
        "telegram token": "TG='7123456789:" + "AAH1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P'",
        "anthropic key": "K='sk-" + "ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'",
        "aws key": "AK" + "IAIOSFODNN7EXAMPLE",
        "google key": "AI" + "zaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
        "assigned secret": 'password = "correcthorsebattery"',
        "bearer header": "Authorization: Bearer abcdef1234567890abcdef",
        "private key block": "-----BEGIN OPENSSH PRIVATE KEY-----",
        "vercel linkage": '{"orgId":"team_x","projectId":"prj_y"}',
        "operator name in a comment": "# runs on the " + "dob" + "by box",
    }
    benign = {
        "svg path data": '<path d="M10.5.3 1.2.4 3.1.9"/>',
        "version string": 'VERSION = "1.2.3"',
        "env var name": 'X_KEYCHAIN_ENV = "CCW_X_KEYCHAIN"',
        "placeholder path": 'p = "' + U + '<you>/.coldcard"',
        "loopback": 'bind = "127.0.0.1"',
        "doc range ip": 'example = "192.0.2.10"',
    }
    # the real GitHub mark: coordinate runs that read as an IP until the geometry is blanked
    gh = ('<svg viewBox="0 0 16 16"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 '
          '7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94Z"/></svg>')
    benign["inline svg mark in html"] = descan(gh)
    # blanking geometry must not blind the gate to a real leak elsewhere in the same page
    samples["ip beside inline svg"] = descan(gh + '\n<p>node at 192.168.1.144</p>')

    missed = [n for n, t in samples.items() if not any(p.search(t) for _, p in RULES)]
    noisy = [n for n, t in benign.items() if any(p.search(t) for _, p in RULES)]
    print(f"catches {len(samples)-len(missed)}/{len(samples)} leak shapes")
    for n in missed:
        print(f"  MISSED  {n}")
    print(f"passes {len(benign)-len(noisy)}/{len(benign)} benign shapes")
    for n in noisy:
        print(f"  FALSE POSITIVE  {n}")
    return 1 if (missed or noisy) else 0


def main():
    if "--selftest" in sys.argv:
        return selftest()
    staged = "--staged" in sys.argv
    files = tracked(staged)
    if not files:
        print("nothing to check")
        return 0

    bad = 0
    for f in files:
        try:
            s = open(f, encoding="utf-8", errors="replace").read()
        except (IsADirectoryError, FileNotFoundError):
            continue
        if f.endswith((".html", ".htm")):
            s = descan(s)
        for label, pat in RULES:
            if exempt(f, label):
                continue
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
