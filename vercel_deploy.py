#!/usr/bin/env python3
"""
vercel_deploy.py — deploy public/ through Vercel's REST API, no CLI.

The CLI was the wrong tool here and it cost a lot of churn. `vercel deploy` first
reads the project's *settings*, which a project-scoped token is not allowed to do, so
it refuses with "Could not retrieve Project Settings" no matter how the token is
passed. The only CLI-compatible credential is an account-scoped one, and the CLI's own
login token expires roughly daily, which is what silently broke deploys mid-afternoon.

The REST API has no such problem: a project-scoped token can upload files and create a
deployment for its own project. So this uploads each file and posts a deployment, and
the tightly-scoped token stays tightly scoped. Nobody has to mint another credential,
on either machine, ever.

The site is eight static files and no build step, which is why this is short.

usage:  vercel_deploy.py [--dir public] [--dry-run]
        deploy(public_dir, token) -> production URL
"""
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://api.vercel.com"
SKIP_DIRS = {".vercel", ".git", "__pycache__"}


def _req(url, token, data=None, headers=None, method=None, timeout=90):
    h = {"Authorization": "Bearer " + token}
    if headers:
        h.update(headers)
    r = urllib.request.Request(url, data=data, headers=h,
                               method=method or ("POST" if data is not None else "GET"))
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        body = resp.read()
        return json.loads(body) if body else {}


def collect(public_dir):
    """Every file to ship, with its sha1. Vercel dedupes by digest, so a file it has
    seen before costs nothing to re-upload."""
    out = []
    for root, dirs, names in os.walk(public_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for n in names:
            if n.startswith("."):
                continue
            full = os.path.join(root, n)
            rel = os.path.relpath(full, public_dir)
            data = open(full, "rb").read()
            out.append({"file": rel, "data": data,
                        "sha": hashlib.sha1(data).hexdigest(), "size": len(data)})
    return sorted(out, key=lambda f: f["file"])


def upload(files, token):
    for f in files:
        _req(f"{API}/v2/files", token, data=f["data"], headers={
            "Content-Type": "application/octet-stream",
            "x-vercel-digest": f["sha"],
            "Content-Length": str(f["size"]),
        })


def create(files, token, project, team_id=None):
    payload = {
        "name": project,
        "project": project,
        "target": "production",
        "files": [{"file": f["file"], "sha": f["sha"], "size": f["size"]} for f in files],
        # A static site with no build. Saying so explicitly means Vercel never needs the
        # project's framework settings, which is the read a project token cannot do.
        "projectSettings": {"framework": None, "buildCommand": None,
                            "installCommand": None, "outputDirectory": None},
    }
    url = f"{API}/v13/deployments"
    if team_id:
        url += f"?teamId={team_id}"
    return _req(url, token, data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"})


def wait_ready(dep_id, token, team_id=None, timeout=180):
    url = f"{API}/v13/deployments/{dep_id}"
    if team_id:
        url += f"?teamId={team_id}"
    t0 = time.time()
    while time.time() - t0 < timeout:
        d = _req(url, token)
        state = d.get("readyState") or d.get("status")
        if state in ("READY", "ERROR", "CANCELED"):
            return state, d
        time.sleep(4)
    return "TIMEOUT", {}


def deploy(public_dir, token, project="coldcard-watch", team_id=None, quiet=False):
    files = collect(public_dir)
    if not files:
        raise RuntimeError(f"no files to deploy in {public_dir}")
    if not quiet:
        print(f"  {len(files)} files, {sum(f['size'] for f in files)/1024:.0f} KB")
    upload(files, token)
    d = create(files, token, project, team_id)
    dep_id, url = d.get("id"), d.get("url")
    state, final = wait_ready(dep_id, token, team_id)
    if state != "READY":
        raise RuntimeError(f"deployment {dep_id} ended {state}: "
                           f"{json.dumps(final.get('errorMessage') or final)[:300]}")
    alias = (final.get("alias") or [None])[0] or url
    if not quiet:
        print(f"  READY  https://{url}")
    return f"https://{alias}"


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    import publish
    pub = os.path.join(here, "public")
    if "--dir" in sys.argv:
        pub = sys.argv[sys.argv.index("--dir") + 1]
    tok = publish.load_env().get("VERCEL_TOKEN")
    if not tok:
        raise SystemExit("no VERCEL_TOKEN; see the README on configuring credentials")
    team = None
    link = os.path.join(pub, ".vercel", "project.json")
    if os.path.exists(link):
        team = json.load(open(link)).get("orgId")
    if "--dry-run" in sys.argv:
        files = collect(pub)
        print(f"  would deploy {len(files)} files from {pub}")
        for f in files:
            print(f"    {f['file']:24} {f['size']:>7} bytes")
        return 0
    print(" ", deploy(pub, tok, team_id=team))
    return 0


if __name__ == "__main__":
    sys.exit(main())
