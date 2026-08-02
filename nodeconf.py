#!/usr/bin/env python3
"""
nodeconf.py — where the block data comes from, without putting anyone's node in the repo.

The scanners used to carry a hardcoded hostname and LAN IP. That is one person's machine,
and it has no business in a public tree: it tells a reader where to find the node and
narrows down who runs it. So the address lives in local config or the environment, and
the code carries only the shape of it.

Resolution order, first hit wins:
  1. env: CCW_NODE_HOST, CCW_NODE_ADDR, CCW_NODE_KEYCHAIN  (or CCW_NODE_RPC_PASSWORD)
  2. a JSON file at ~/.coldcard-node.json, or wherever CCW_NODE_CONFIG points
  3. nothing, and callers fall back to public block APIs

Nothing here has a default that points anywhere real. A repo checkout with no config and
no environment reads from public explorers, which is what a contributor needs in order to
reproduce the work at all.
"""
import json
import os
import subprocess

CONFIG = os.environ.get("CCW_NODE_CONFIG",
                        os.path.expanduser("~/.coldcard-node.json"))

_cache = None


def _file():
    if not os.path.exists(CONFIG):
        return {}
    try:
        with open(CONFIG, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def node():
    """Returns {host, addr, keychain|password} or {} when no node is configured.

    host      the TLS SNI / Host header name the node answers to
    addr      the address actually dialled (IP or hostname)
    keychain  macOS Keychain service holding the RPC password, read on demand
    password  the RPC password directly, for environments without a Keychain
    """
    global _cache
    if _cache is not None:
        return _cache
    f = _file()
    cfg = {
        "host": os.environ.get("CCW_NODE_HOST") or f.get("host"),
        "addr": os.environ.get("CCW_NODE_ADDR") or f.get("addr"),
        "keychain": os.environ.get("CCW_NODE_KEYCHAIN") or f.get("keychain"),
        "password": os.environ.get("CCW_NODE_RPC_PASSWORD") or f.get("password"),
    }
    _cache = cfg if (cfg["addr"] and (cfg["keychain"] or cfg["password"])) else {}
    return _cache


def have_node():
    return bool(node())


def rpc_password():
    cfg = node()
    if not cfg:
        raise RuntimeError("no node configured; see nodeconf.py")
    if cfg.get("password"):
        return cfg["password"]
    return subprocess.run(
        ["security", "find-generic-password", "-s", cfg["keychain"], "-w"],
        capture_output=True, text=True).stdout.strip()


def describe():
    """A one-line summary safe to print: never the address itself."""
    cfg = node()
    if not cfg:
        return "no node configured; using public block APIs"
    return ("node configured via "
            + ("environment" if os.environ.get("CCW_NODE_ADDR") else CONFIG))
