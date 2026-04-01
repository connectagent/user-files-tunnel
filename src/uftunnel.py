#!/usr/bin/env python3
"""
fstunnel.py — connects to fsrelay via WebSocket and executes incoming
file-system commands on the local machine using LocalFileSystem.

The tunnel keeps reconnecting automatically so the relay can be restarted
without restarting the tunnel.

Usage:
    pip install websockets
    python fstunnel.py --relay-url ws://relay-host:8081/tunnel

Protocol (JSON over WebSocket):
    Incoming (relay → tunnel):
        {"id": "<uuid>", "command": "<method_name>", "params": {…}}
    Outgoing (tunnel → relay):
        {"id": "<uuid>", "result": {"ok": true/false, "data": …, "error": …}}
"""
from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys
import time
from urllib.parse import urlparse

# Ensure stdout/stderr handle unicode on Windows (cp1252 by default)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import websockets
except ImportError:
    print("ERROR: 'websockets' package required.  Run: pip install websockets")
    sys.exit(1)

from pathlib import Path
from model import LocalFileSystem, terminate_all_procs
from policy import Policy
from config import load_config, get_config_path, get_policy_path

FS = LocalFileSystem()

# Policy hot-reload state
POLICY_PATH:  Path | None  = None
POLICY_MTIME: float | None = None


def _check_policy_reload() -> None:
    """Reload the policy from disk if the file has changed since last load."""
    global POLICY_MTIME
    if POLICY_PATH is None:
        return
    try:
        mtime = POLICY_PATH.stat().st_mtime
    except OSError:
        return
    if mtime == POLICY_MTIME:
        return
    try:
        policy = Policy.from_file(str(POLICY_PATH))
        FS._policy = policy
        POLICY_MTIME = mtime
        print(f"[fstunnel] Policy reloaded from {POLICY_PATH}")
    except Exception as e:
        print(f"[fstunnel] Failed to reload policy: {e}", file=sys.stderr)


# All commands the relay may call (cd is handled specially before LocalFileSystem dispatch)
COMMANDS = {
    "read_file",
    "write_file",
    "edit_file",
    "list_directory",
    "create_directory",
    "delete_file",
    "move_file",
    "glob_files",
    "grep_files",
    "file_info",
    "touch_file",
    "exec_file",
    "get_policy",
    "set_policy",
    "options_browse",
    "options_browse_favorites",
    "cd",
    "cp",
}

# Current working directory — set from default_dir in settings; updated by cd
CURRENT_DIR: str | None = None  # set at startup from settings-tunnel.json

# Ask-before-apply mode for remote policy changes
ASK_POLICY: bool = False

# Ask-before-access mode — prompt before every file system operation
ASK_ACCESS: bool = False

# "Remember" cache — keyed by (access_right, path_str), value = expiry timestamp
_ACCESS_REMEMBER:  dict[tuple[str, str], float] = {}
# Expiry timestamp for remembered policy approvals (single global window)
_POLICY_REMEMBER_UNTIL: float = 0.0
_REMEMBER_SECONDS = 300  # 5 minutes

# Required access right for each command (used by ASK_ACCESS prompts)
_CMD_ACCESS: dict[str, str] = {
    "read_file":               "read",
    "list_directory":          "read",
    "glob_files":              "read",
    "grep_files":              "read",
    "file_info":               "read",
    "options_browse":          None,   # internal UI helper, no confirmation needed
    "write_file":              "write",
    "edit_file":               "write",
    "delete_file":             "write",
    "create_directory":        "write",
    "touch_file":              "write",
    "move_file":               "write",
    "cp":                      "write",
    "exec_file":               "execute",
    "options_browse_favorites": None,   # internal, no confirmation needed
    "get_policy":              None,
    "set_policy":              None,    # handled separately by ASK_POLICY
    "cd":                      "read",
}

_ACCESS_TYPES = ("deny", "read", "read_execute", "write", "write_execute", "copy_on_write")


def _read_tty_line(prompt: str) -> str:
    """Read a line directly from the controlling terminal, bypassing sys.stdin.

    asyncio's event loop owns sys.stdin on the main thread; calling input() from
    a thread-pool executor races with it and typically returns an empty string.
    Opening /dev/tty (Unix) or using msvcrt (Windows) avoids that entirely.
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        if sys.platform == "win32":
            import msvcrt
            chars: list[str] = []
            while True:
                ch = msvcrt.getwche()
                if ch in ("\r", "\n"):
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    break
                chars.append(ch)
            return "".join(chars).strip().lower()
        else:
            with open("/dev/tty") as tty:
                return tty.readline().strip().lower()
    except (OSError, EOFError):
        return ""


def _policy_diff(old: dict, new: dict) -> list[str]:
    """Return human-readable lines describing what changed between two policy dicts."""
    old_map: dict[str, str] = {}
    for atype in _ACCESS_TYPES:
        for p in old.get(atype) or []:
            old_map[str(p)] = atype
    new_map: dict[str, str] = {}
    for atype in _ACCESS_TYPES:
        for p in new.get(atype) or []:
            new_map[str(p)] = atype

    lines = []
    for path in sorted(set(old_map) | set(new_map)):
        old_a = old_map.get(path)
        new_a = new_map.get(path)
        if old_a is None:
            lines.append(f"  + {path}  ({new_a})")
        elif new_a is None:
            lines.append(f"  - {path}  ({old_a})")
        elif old_a != new_a:
            lines.append(f"  ~ {path}  ({old_a} -> {new_a})")
    return lines


def _resolve_path(path: str | None) -> str:
    """Resolve *path* against CURRENT_DIR when it is relative or absent."""
    if not path or path == ".":
        return CURRENT_DIR or "."
    p = Path(path)
    if not p.is_absolute() and CURRENT_DIR:
        return str(Path(CURRENT_DIR) / path)
    return path


def _cmd_cd(path: str) -> dict:
    global CURRENT_DIR
    if not path:
        return {"ok": True, "data": {"path": CURRENT_DIR or "."}, "error": None}
    resolved = str(Path(_resolve_path(path)).resolve())
    if FS._policy.check(resolved, "list_directory") == "Deny":
        return {"ok": False, "data": None, "error": f"Access denied by policy: {resolved}"}
    p = Path(resolved)
    if not p.exists():
        return {"ok": False, "data": None, "error": f"Directory not found: {resolved}"}
    if not p.is_dir():
        return {"ok": False, "data": None, "error": f"Not a directory: {resolved}"}
    CURRENT_DIR = resolved
    print(f"[fstunnel] cd -> {CURRENT_DIR}")
    return {"ok": True, "data": {"path": CURRENT_DIR}, "error": None}


def dispatch(command: str, params: dict) -> dict:
    """Execute *command* with *params* using LocalFileSystem, return FSResult dict."""
    _check_policy_reload()

    if command == "set_policy" and ASK_POLICY:
        global _POLICY_REMEMBER_UNTIL
        new_policy = {t: params.get(t) or [] for t in _ACCESS_TYPES}
        changes = _policy_diff(FS._policy_dict(), new_policy)
        if changes:
            if time.time() < _POLICY_REMEMBER_UNTIL:
                print("[fstunnel] Policy change auto-approved (remembered).")
            else:
                print("\n[fstunnel] Remote policy change requested:")
                print("\n".join(changes))
                answer = _read_tty_line("Confirm changes? [y/N/r] ")
                if answer == "r":
                    _POLICY_REMEMBER_UNTIL = time.time() + _REMEMBER_SECONDS
                    print(f"[fstunnel] Policy change accepted and remembered for {_REMEMBER_SECONDS // 60} minutes.")
                elif answer == "y":
                    print("[fstunnel] Policy change accepted.")
                else:
                    print("[fstunnel] Policy change rejected.")
                    return {"ok": False, "data": None, "error": "Policy change rejected by user"}

    if command == "cd":
        return _cmd_cd(params.get("path", "."))

    # Resolve path params against CURRENT_DIR
    if "path" in params:
        params = {**params, "path": _resolve_path(params["path"])}
    if "src" in params:
        params = {**params, "src": _resolve_path(params["src"])}
    if "dst" in params:
        params = {**params, "dst": _resolve_path(params["dst"])}

    if command not in COMMANDS:
        return {"ok": False, "data": None, "error": f"Unknown command: {command}"}

    if ASK_ACCESS:
        required = _CMD_ACCESS.get(command)
        if required is not None:
            paths = []
            for key in ("path", "src", "dst"):
                if key in params:
                    paths.append(params[key])
            path_str = ", ".join(paths) if paths else "(no path)"
            cache_key = (required, path_str)
            if time.time() < _ACCESS_REMEMBER.get(cache_key, 0.0):
                print(f"[fstunnel] Access auto-approved (remembered): {command} {path_str}")
            else:
                print(f"\n[fstunnel] Access request: {command} {path_str}  (requires: {required})")
                answer = _read_tty_line("Allow? [y/N/r] ")
                if answer == "r":
                    _ACCESS_REMEMBER[cache_key] = time.time() + _REMEMBER_SECONDS
                    print(f"[fstunnel] Access allowed and remembered for {_REMEMBER_SECONDS // 60} minutes.")
                elif answer != "y":
                    print("[fstunnel] Access denied by user.")
                    return {"ok": False, "data": None, "error": "Access denied by user"}

    method = getattr(FS, command, None)
    if method is None:
        return {"ok": False, "data": None, "error": f"Method not found: {command}"}
    try:
        result = method(**params)
        return result.to_dict()
    except TypeError as e:
        print(f"[fstunnel] Parameter error in {command!r}: {e}", file=sys.stderr)
        return {"ok": False, "data": None, "error": f"Parameter error: {e}"}
    except Exception as e:
        print(f"[fstunnel] Error in {command!r}: {type(e).__name__}: {e}", file=sys.stderr)
        return {"ok": False, "data": None, "error": str(e)}


# ---------------------------------------------------------------------------
# WebSocket loop
# ---------------------------------------------------------------------------

def _normalize_relay_url(url: str) -> str:
    """Convert http(s):// to ws(s):// and ensure path ends with /tunnel."""
    url = url.replace("http://", "ws://", 1).replace("https://", "wss://", 1)
    parsed = urlparse(url)
    if not parsed.path or parsed.path == "/":
        url = url.rstrip("/") + "/tunnel"
    return url


async def _ping_loop(ws) -> None:
    """Send a ping every 5 s and close the socket if no pong arrives within 15 s."""
    while True:
        await asyncio.sleep(5)
        try:
            print("[fstunnel] ping to relay ->", flush=True)
            pong_waiter = await ws.ping()
            await asyncio.wait_for(pong_waiter, timeout=15.0)
            print("[fstunnel] <- pong from relay", flush=True)
        except asyncio.TimeoutError:
            print("[fstunnel] ping from trlay timeout (15 s) — closing connection", flush=True)
            await ws.close()
            return
        except Exception as exc:
            print(f"[fstunnel] ping from relay loop ended: {exc}", flush=True)
            return


async def tunnel_loop(relay_url: str, token: str, user_id: str | None = None,
                      reconnect_delay: float = 5.0):
    relay_url = _normalize_relay_url(relay_url)
    # Append token + hostname + user_id to URL so relay can route and identify this tunnel
    sep = "&" if "?" in relay_url else "?"
    hostname = socket.gethostname()
    connect_url = f"{relay_url}{sep}token={token}&hostname={hostname}"
    if user_id:
        connect_url += f"&user_id={user_id}"

    async def _handle_call(ws, raw_message: str) -> None:
        """Parse, dispatch, and reply to one relay command — runs as a concurrent task."""
        call_id = None
        result = None
        try:
            try:
                msg = json.loads(raw_message)
            except json.JSONDecodeError as e:
                print(f"[fstunnel] Bad JSON from relay: {e}")
                return

            if not isinstance(msg, dict):
                print(f"[fstunnel] Ignoring non-dict message: {type(msg).__name__}")
                return

            call_id = msg.get("id")
            command = msg.get("command", "")
            params = msg.get("params", {})

            if isinstance(params, dict):
                params_str = ", ".join(f"{k}={v!r}" for k, v in params.items())
            else:
                params_str = repr(params)
            print(f"[fstunnel] <- {command}({params_str})")

            loop = asyncio.get_event_loop()
            t0 = loop.time()
            result = await loop.run_in_executor(None, dispatch, command, params)
            elapsed = loop.time() - t0
            print(f"[fstunnel] -> ok={result['ok']} ({elapsed:.2f}s)")

        except Exception as e:
            err = f"Tunnel processing error: {type(e).__name__}: {e}"
            print(f"[fstunnel] {err}")
            result = {"ok": False, "data": None, "error": err}

        if call_id is not None and result is not None:
            try:
                response = json.dumps({"id": call_id, "result": result})
                await ws.send(response)
            except websockets.exceptions.ConnectionClosed:
                pass  # main loop will detect disconnect and reconnect
            except Exception as e:
                print(f"[fstunnel] Error sending response (call_id={call_id}): {type(e).__name__}: {e}", file=sys.stderr)

    while True:
        try:
            print(f"[fstunnel] Connecting to {relay_url} …")
            async with websockets.connect(connect_url,
                                          max_size=64 * 1024 * 1024,
                                          ping_interval=None,  # managed by _ping_loop
                                          ) as ws:
                print(f"[fstunnel] Connected with user_id: {user_id}.")
                ping_task = asyncio.create_task(_ping_loop(ws))
                try:
                    async for raw_message in ws:
                        asyncio.create_task(_handle_call(ws, raw_message))
                finally:
                    ping_task.cancel()

        except (
            websockets.exceptions.ConnectionClosed,
            ConnectionRefusedError,
            OSError,
        ) as e:
            print(f"[fstunnel] Disconnected ({type(e).__name__}): {e}. Reconnecting in {reconnect_delay}s …")
            await asyncio.sleep(reconnect_delay)
        except Exception as e:
            print(f"[fstunnel] Unexpected error ({type(e).__name__}): {e}. Reconnecting in {reconnect_delay}s …", file=sys.stderr)
            await asyncio.sleep(reconnect_delay)


# ---------------------------------------------------------------------------
# Default policy creation
# ---------------------------------------------------------------------------

def _create_default_policy() -> str:
    """Create a default policy file next to this script and return its path.

    Deny rules cover all filesystem roots (all drive letters on Windows, / on
    Unix), then copy_on_write is granted for the user's Documents and Downloads.
    First-match-wins means anything not under those two folders is denied.
    """
    import platform
    home = Path.home()

    # --- Deny rules: all filesystem roots ---
    deny_paths: list[str] = []
    if platform.system() == "Windows":
        import string
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if Path(root).exists():
                deny_paths.append(root)
    else:
        deny_paths.append("/")

    # --- copy_on_write: Documents and Downloads ---
    candidates = [home / "Documents", home / "Downloads"]
    cow_dirs = [p for p in candidates if p.exists()]
    if not cow_dirs:
        cow_dirs = [home]   # fallback: home itself

    data = (
        [{"path": p, "rights": "deny"} for p in deny_paths]
        + [{"path": str(p), "rights": "copy_on_write"} for p in cow_dirs]
    )

    policy_path = get_policy_path()
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    for p in deny_paths:
        print(f"[fstunnel] Default policy: {p}:deny")
    for p in cow_dirs:
        print(f"[fstunnel] Default policy: {p}:copy_on_write  -> {policy_path}")
    return str(policy_path)


# ---------------------------------------------------------------------------
# Default directory resolution
# ---------------------------------------------------------------------------

def _resolve_default_dir(preferred: str) -> str:
    """Return *preferred* if accessible per policy, else the first accessible
    policy directory (copy_on_write → write → read), else *preferred* as-is.
    """
    policy = FS._policy

    def accessible(path: str) -> bool:
        try:
            p = Path(path)
            return p.is_dir() and policy.check(path, "list_directory") == "Allow"
        except Exception:
            return False

    if accessible(preferred):
        print(f"[fstunnel] Default dir: {preferred}")
        return preferred

    # Walk policy lists in priority order to find first accessible directory
    for folder_list in (policy._copy_on_write, policy._write, policy._read):
        for folder in folder_list:
            candidate = str(folder)
            if accessible(candidate):
                print(f"[fstunnel] Default dir {preferred!r} not accessible; "
                      f"falling back to {candidate!r}")
                return candidate

    # Nothing accessible — use preferred anyway (will fail later on use)
    print(f"[fstunnel] Warning: default dir {preferred!r} not accessible per policy "
          f"and no fallback found; using as-is.", file=sys.stderr)
    return preferred


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="fstunnel — local agent that executes relay commands")
    parser.add_argument(
        "--relay-url",
        default=None,
        metavar="URL",
        help="WebSocket URL of fsrelay (default: ws://localhost:5051/tunnel)",
    )
    parser.add_argument(
        "--token",
        default=None,
        metavar="TOKEN",
        help="Auth token to identify this tunnel (required unless --token-file is used)",
    )
    parser.add_argument(
        "--token-file",
        default=None,
        metavar="FILE",
        help="Path to a file whose first non-empty line is the auth token",
    )
    parser.add_argument(
        "--reconnect-delay",
        type=float,
        default=5.0,
        metavar="SECS",
        help="Seconds to wait between reconnection attempts (default: 5)",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Erase settings-tunnel.json and default.policy, then exit",
    )
    parser.add_argument(
        "--ask-policy",
        action="store_true",
        help="Prompt for confirmation before applying any remotely-requested policy change",
    )
    parser.add_argument(
        "--ask-access",
        action="store_true",
        help="Prompt for confirmation before every file system operation, showing the operation and required access right",
    )
    args = parser.parse_args()

    if args.reset:
        settings_path = get_config_path()
        policy_path   = get_policy_path()
        empty = {"relay_url": "", "token": "", "default_dir": "", "policy_file": ""}
        settings_path.write_text(json.dumps(empty, indent=2), encoding="utf-8")
        print(f"[fstunnel] Reset: {settings_path}")
        if policy_path.exists():
            policy_path.unlink()
            print(f"[fstunnel] Deleted: {policy_path}")
        return

    settings = load_config() or {}
    relay_url=args.relay_url
    if args.relay_url is None:
        relay_url = settings.get("relay_url")
    if args.token is None:
        args.token = settings.get("token") or None

    if not args.token:
        from bootstrap import bootstrap
        print("[fstunnel] No token configured — starting device authorization flow...")
        user_id, token, tunnel_url = bootstrap()
        args.token = token
        #if not args.relay_url:
        #    args.relay_url = tunnel_url
        # Persist to settings so next startup skips bootstrap
        settings["token"] = token
        #settings["relay_url"] = tunnel_url
        settings["user_id"] = user_id
        config_path = get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[fstunnel] Credentials saved to {config_path}")

    if args.relay_url is None:
        #args.relay_url = "ws://localhost:5051/tunnel"

        from overrides import RELAY_URL
        relay_url=RELAY_URL


    global POLICY_PATH, POLICY_MTIME, ASK_POLICY, ASK_ACCESS
    ASK_POLICY = args.ask_policy
    ASK_ACCESS = args.ask_access
    if ASK_POLICY:
        print("[fstunnel] Ask-policy mode: remote policy changes require confirmation.")
    if ASK_ACCESS:
        print("[fstunnel] Ask-access mode: every file system operation requires confirmation.")
    policy_file = settings.get("policy_file") or str(get_policy_path())
    if not get_policy_path().exists():
        policy_file = _create_default_policy()
    if policy_file:
        POLICY_PATH = Path(policy_file)
        try:
            FS._policy = Policy.from_file(str(POLICY_PATH))
            POLICY_MTIME = POLICY_PATH.stat().st_mtime
            print(f"[fstunnel] Policy loaded from {POLICY_PATH}")
        except Exception as e:
            print(f"[fstunnel] Warning: could not load policy file {POLICY_PATH}: {e}", file=sys.stderr)

    global CURRENT_DIR
    CURRENT_DIR = _resolve_default_dir(settings.get("default_dir") or str(Path.home()))

    token = args.token
    if not token and args.token_file:
        try:
            for line in Path(args.token_file).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    token = line
                    break
        except OSError as e:
            parser.error(f"Cannot read token file {args.token_file!r}: {e}")
    if not token:
        parser.error("--token or --token-file is required")

    try:
        user_id = settings.get("user_id")
        asyncio.run(tunnel_loop(relay_url, token, user_id=user_id,
                                reconnect_delay=args.reconnect_delay))
    except KeyboardInterrupt:
        terminate_all_procs()
        print("\n[fstunnel] Stopped.")


if __name__ == "__main__":
    main()
