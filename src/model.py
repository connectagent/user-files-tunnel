"""
model.py — LocalFileSystem: core file-system operations used by all other components.
"""
from __future__ import annotations

import fnmatch
import functools
import platform
import glob as _glob
import os
import re
import shutil
import stat
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from policy import Policy



# ---------------------------------------------------------------------------
# Windows known-folder helper
# ---------------------------------------------------------------------------

def _win_known_folder(guid_str: str) -> Path | None:
    """Return the actual path of a Windows known folder via SHGetKnownFolderPath.

    Handles user-redirected folders (e.g. Documents moved to D:\\).
    Returns None on failure so callers can fall back to home / name.
    """
    try:
        import ctypes
        import ctypes.wintypes
        import uuid
        fn = ctypes.windll.shell32.SHGetKnownFolderPath
        fn.restype = ctypes.HRESULT
        g = uuid.UUID(guid_str)
        guid_buf = (ctypes.c_byte * 16)(*g.bytes_le)
        ptr = ctypes.c_wchar_p()
        if fn(ctypes.byref(guid_buf), 0, None, ctypes.byref(ptr)) == 0:
            return Path(ptr.value)
    except Exception:
        pass
    return None


_WIN_FOLDER_GUIDS = {
    "Documents": "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
    "Downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
    "Pictures":  "{33E28130-4E1E-4676-835A-98395C3BC3BB}",
    "Desktop":   "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
}


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class FSResult:
    ok: bool
    data: Any = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {"ok": self.ok, "data": self.data, "error": self.error}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _fs_op(method):
    """Decorator: wrap a LocalFileSystem method in a standard try/except."""
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except Exception as e:
            return FSResult(ok=False, error=str(e))
    return wrapper


def _ts_iso(ts: float) -> str:
    """Convert a POSIX timestamp to an ISO-8601 string."""
    return datetime.fromtimestamp(ts).isoformat()


def _entry_dict(entry, s) -> dict:
    """Build the standard name/type/size/modified dict for a directory entry."""
    return {
        "name": entry.name,
        "type": "dir" if entry.is_dir() else "file",
        "size": s.st_size,
        "modified": _ts_iso(s.st_mtime),
    }


# ---------------------------------------------------------------------------
# Active-process registry — lets terminate_all_procs() clean up on shutdown
# ---------------------------------------------------------------------------

_active_procs: set[subprocess.Popen] = set()
_active_procs_lock = threading.Lock()


def _register_proc(proc: subprocess.Popen) -> None:
    with _active_procs_lock:
        _active_procs.add(proc)


def _unregister_proc(proc: subprocess.Popen) -> None:
    with _active_procs_lock:
        _active_procs.discard(proc)


def terminate_all_procs() -> None:
    """Terminate every subprocess still running from exec_file calls.

    Called by the tunnel on shutdown so no orphan processes are left behind.
    Each process receives terminate() first; if it does not exit within one
    second it is killed unconditionally.
    """
    with _active_procs_lock:
        procs = list(_active_procs)
    for proc in procs:
        try:
            if proc.poll() is None:          # still running
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# LocalFileSystem
# ---------------------------------------------------------------------------

class LocalFileSystem:
    """All file-system operations used by the CLI, server, and tunnel."""

    def __init__(self, policy: Policy | None = None):
        # Default Policy() → empty blacklist/whitelist → AskConfirmation always
        # returns "Allow", so behaviour is unchanged when no policy is passed.
        self._policy = policy if policy is not None else Policy()

    def _check(self, path: str, operation: str) -> FSResult | None:
        """Return a Deny FSResult if the policy rejects *path*, else None."""
        if self._policy.check(path, operation) != "Allow":
            return FSResult(ok=False, error=f"Access denied by policy: {path}")
        return None

    def _policy_dict(self) -> dict:
        """Serialize the active policy lists to JSON-safe strings."""
        p = self._policy
        return {
            "deny":          [str(f) for f in p._deny],
            "read":          [str(f) for f in p._read],
            "read_execute":  [str(f) for f in p._read_execute],
            "write":         [str(f) for f in p._write],
            "write_execute": [str(f) for f in p._write_execute],
            "copy_on_write": [str(f) for f in p._copy_on_write],
        }

    # ------------------------------------------------------------------
    # read_file
    # ------------------------------------------------------------------
    @_fs_op
    def read_file(self, path: str, encoding: str = "utf-8") -> FSResult:
        """Return the content of *path*.

        Text files are returned as a UTF-8 string.
        Binary files (or files that fail text decoding) are returned as a
        base64-encoded string with ``encoding`` set to ``"base64"`` in the
        result so the caller can decode them correctly.

        When copy_on_write is enabled and an Agent's Copy of the file exists,
        the copy is read instead of the original.
        """
        if err := self._check(path, "read_file"):
            return err
        actual = self._policy.copy_path(path)
        if actual != path and Path(actual).exists():
            path = actual
        raw = Path(path).read_bytes()
        if encoding != "base64":
            try:
                content = raw.decode(encoding)
                return FSResult(ok=True, data={"content": content, "path": str(path), "encoding": encoding})
            except (UnicodeDecodeError, LookupError):
                pass
        import base64
        content = base64.b64encode(raw).decode("ascii")
        return FSResult(ok=True, data={"content": content, "path": str(path), "encoding": "base64"})

    # ------------------------------------------------------------------
    # write_file
    # ------------------------------------------------------------------
    @_fs_op
    def write_file(self, path: str, content: str, encoding: str = "utf-8") -> FSResult:
        """Write *content* to *path*, creating parent directories if needed.

        When *encoding* is ``"base64"``, *content* is decoded from base64 and
        written as raw bytes (for binary files).  Otherwise *content* is written
        as text with the given encoding.

        When copy_on_write is enabled, writes to the Agent's Copy instead of
        the original file, leaving the original untouched.
        """
        if err := self._check(path, "write_file"):
            return err
        actual = self._policy.copy_path(path)
        p = Path(actual)
        p.parent.mkdir(parents=True, exist_ok=True)
        if encoding == "base64":
            import base64
            raw = base64.b64decode(content)
            p.write_bytes(raw)
            return FSResult(ok=True, data={"path": str(actual), "bytes": len(raw)})
        p.write_text(content, encoding=encoding)
        return FSResult(ok=True, data={"path": str(actual), "bytes": len(content.encode(encoding))})

    # ------------------------------------------------------------------
    # edit_file
    # ------------------------------------------------------------------
    @_fs_op
    def edit_file(
        self,
        path: str,
        old_string: str,
        new_string: str,
        replace_all: bool = False,
        encoding: str = "utf-8",
    ) -> FSResult:
        """Replace the first (or all) occurrence of *old_string* with *new_string*.

        When copy_on_write is enabled, reads from the Agent's Copy if it exists
        (falling back to the original), and always writes the result to the copy.
        The original file is never modified.
        """
        if err := self._check(path, "edit_file"):
            return err
        copy = self._policy.copy_path(path)
        # Read from copy if it already exists, otherwise from the original.
        read_path = copy if (copy != path and Path(copy).exists()) else path
        original = Path(read_path).read_text(encoding=encoding)
        if old_string not in original:
            return FSResult(ok=False, error=f"old_string not found in {read_path}")
        count = original.count(old_string)
        if replace_all:
            updated = original.replace(old_string, new_string)
            replaced = count
        else:
            updated = original.replace(old_string, new_string, 1)
            replaced = 1
        Path(copy).write_text(updated, encoding=encoding)
        return FSResult(ok=True, data={"path": str(copy), "replacements": replaced})

    # ------------------------------------------------------------------
    # list_directory
    # ------------------------------------------------------------------
    @_fs_op
    def list_directory(self, path: str = ".") -> FSResult:
        """List entries in *path*, silently excluding any denied by policy."""
        if err := self._check(path, "list_directory"):
            return err
        p = Path(path)
        entries = []
        for entry in sorted(p.iterdir()):
            if self._policy.check(str(entry), "list_directory") != "Allow":
                continue  # silently exclude denied entries
            try:
                s = entry.stat()
            except OSError:
                continue  # skip dead symlinks and unreadable entries
            entries.append(_entry_dict(entry, s))
        return FSResult(ok=True, data={"path": str(p.resolve()), "entries": entries})

    # ------------------------------------------------------------------
    # create_directory
    # ------------------------------------------------------------------
    @_fs_op
    def create_directory(self, path: str) -> FSResult:
        """Create *path* (and all parents) if it does not exist.

        Under copy_on_write policy, the directory is created with the
        configured suffix so it is treated as an agent copy.
        """
        if err := self._check(path, "create_directory"):
            return err
        actual = self._policy.copy_path(path)
        Path(actual).mkdir(parents=True, exist_ok=True)
        return FSResult(ok=True, data={"path": str(Path(actual).resolve())})

    # ------------------------------------------------------------------
    # delete_file
    # ------------------------------------------------------------------
    @_fs_op
    def delete_file(self, path: str, recursive: bool = False) -> FSResult:
        """Delete a file or directory.  Use *recursive=True* for directories.

        When copy_on_write is enabled, deletes only the Agent's Copy, leaving
        the original file untouched.
        """
        if err := self._check(path, "delete_file"):
            return err
        actual = self._policy.copy_path(path)
        p = Path(actual)
        if p.is_dir():
            if recursive:
                shutil.rmtree(p)
            else:
                p.rmdir()  # only works when empty
        else:
            p.unlink()
        return FSResult(ok=True, data={"path": str(actual)})

    # ------------------------------------------------------------------
    # move_file
    # ------------------------------------------------------------------
    @_fs_op
    def move_file(self, src: str, dst: str) -> FSResult:
        """Move / rename *src* to *dst*.

        When copy_on_write is enabled, the destination is redirected to the
        Agent's Copy path so the original destination file is not overwritten.
        """
        if err := self._check(src, "move_file"):
            return err
        if err := self._check(dst, "move_file"):
            return err
        actual_dst = self._policy.copy_path(dst)
        dst_path = Path(actual_dst)
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(src, actual_dst)
        return FSResult(ok=True, data={"src": str(src), "dst": str(actual_dst)})

    # ------------------------------------------------------------------
    # cp
    @_fs_op
    def cp(self, data: str, dst: str) -> FSResult:
        """Unpack a base64 tar.gz archive produced by cp_export() into *dst*.

        Only write access is required.  The source data was already read on the
        remote machine with read-only permission.

        Destination semantics follow Unix cp -r:
          - If *dst* already exists as a directory, the archive root is placed
            inside it (dst/<archive_root_name>).
          - Otherwise the archive root is created as *dst*.
        """
        import base64
        import io
        import tarfile
        import tempfile

        if err := self._check(dst, "write_file"):
            return err

        dst_path = Path(self._policy.copy_path(dst))
        buf = io.BytesIO(base64.b64decode(data))

        with tempfile.TemporaryDirectory() as tmpdir:
            with tarfile.open(fileobj=buf, mode="r:gz") as tar:
                tar.extractall(tmpdir)

            roots = list(Path(tmpdir).iterdir())
            if not roots:
                return FSResult(ok=False, error="Archive is empty")
            extracted_root = roots[0]

            file_count = (
                sum(1 for f in extracted_root.rglob("*") if f.is_file())
                if extracted_root.is_dir() else 1
            )

            if dst_path.is_dir():
                final = dst_path / extracted_root.name
            else:
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                final = dst_path

            if final.exists():
                shutil.rmtree(str(final)) if final.is_dir() else final.unlink()
            shutil.move(str(extracted_root), str(final))

        return FSResult(ok=True, data={"dst": str(final), "files": file_count})

    # ------------------------------------------------------------------
    # glob_files
    # ------------------------------------------------------------------
    @_fs_op
    def glob_files(self, pattern: str, path: str = ".") -> FSResult:
        """Find files matching *pattern* (glob) rooted at *path*,
        silently excluding matches denied by policy."""
        if err := self._check(path, "glob_files"):
            return err
        root = Path(path).resolve()
        matches = sorted(
            str(Path(m).resolve())
            for m in _glob.glob(str(root / pattern), recursive=True)
            if self._policy.check(str(Path(m).resolve()), "glob_files") == "Allow"
        )
        return FSResult(ok=True, data={"pattern": pattern, "path": str(root), "matches": matches})

    # ------------------------------------------------------------------
    # grep_files
    # ------------------------------------------------------------------
    @_fs_op
    def grep_files(
        self,
        pattern: str,
        path: str = ".",
        file_glob: str = "*",
        ignore_case: bool = False,
        max_results: int = 200,
    ) -> FSResult:
        """Search file contents for *pattern* (regex) under *path*,
        silently excluding files denied by policy."""
        if err := self._check(path, "grep_files"):
            return err
        flags = re.IGNORECASE if ignore_case else 0
        rx = re.compile(pattern, flags)
        root = Path(path).resolve()
        results: list[dict] = []
        for filepath in sorted(root.rglob(file_glob)):
            if not filepath.is_file():
                continue
            if self._policy.check(str(filepath), "grep_files") != "Allow":
                continue  # silently skip denied files
            try:
                text = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue  # skip files we cannot read (permission denied, etc.)
            for lineno, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    results.append({"file": str(filepath), "line": lineno, "text": line})
                    if len(results) >= max_results:
                        return FSResult(ok=True, data={"results": results, "truncated": True})
        return FSResult(ok=True, data={"results": results, "truncated": False})

    # ------------------------------------------------------------------
    # options_browse
    # ------------------------------------------------------------------
    @_fs_op
    def options_browse(self, path: str = "/") -> FSResult:
        """List subdirectories at *path* without applying any policy checks.

        Intended exclusively for the policy management UI so the user can
        browse the full directory tree when configuring access rights —
        independent of the policy currently in effect.
        """
        # Folders always shown regardless of hidden/system flags
        _ALWAYS_SHOW = {"Documents", "Downloads", "Pictures", "Desktop",
                        "Music", "Videos"}
        _WIN_HIDDEN  = 0x02
        _WIN_SYSTEM  = 0x04
        _MAC_UF_HIDDEN = 0x8000   # UF_HIDDEN — set on Library, etc.
        _system = platform.system()

        p = Path(path).expanduser()
        resolved = str(p.resolve())
        dirs = []
        try:
            raw = list(os.scandir(resolved))
        except OSError as e:
            print(f"[fstunnel] options_browse {resolved!r} -> scandir error: {e}", flush=True)
            raw = []
        for entry in sorted(raw, key=lambda e: e.name.lower()):
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                s = entry.stat(follow_symlinks=False)
                if entry.name not in _ALWAYS_SHOW:
                    if _system == "Windows":
                        if s.st_file_attributes & (_WIN_HIDDEN | _WIN_SYSTEM):
                            continue
                    elif _system == "Darwin":
                        if entry.name.startswith("."):
                            continue
                        if getattr(s, "st_flags", 0) & _MAC_UF_HIDDEN:
                            continue
                dirs.append(_entry_dict(entry, s))
            except OSError:
                continue
        names = [d["name"] for d in dirs]
        print(f"[fstunnel] options_browse {resolved!r} -> {len(dirs)} dirs: {names}", flush=True)
        return FSResult(ok=True, data={"path": resolved, "entries": dirs})

    # ------------------------------------------------------------------
    # options_browse_favorites
    # ------------------------------------------------------------------

    def options_browse_favorites(self) -> FSResult:
        """Return platform-appropriate favourite folders for the browser UI.

        Windows : all existing drive roots  (C:\\, D:\\, …)
        macOS   : / plus every entry under /Volumes
        Linux   : /
        Home directory is always prepended.
        """
        import platform
        system = platform.system()
        home = Path.home()
        items: list[dict] = [{"label": "Home", "path": str(home), "icon": "home"}]

        if system == "Windows":
            for name, guid in _WIN_FOLDER_GUIDS.items():
                p = _win_known_folder(guid) or (home / name)
                if p.is_dir():
                    items.append({"label": name, "path": str(p), "icon": "home"})
            import string
            for letter in string.ascii_uppercase:
                root = f"{letter}:\\"
                if Path(root).exists():
                    items.append({"label": f"{letter}:", "path": root, "icon": "disk"})
        elif system == "Darwin":
            for name in ("Documents", "Downloads", "Pictures", "Desktop"):
                p = home / name
                if p.is_dir():
                    items.append({"label": name, "path": str(p), "icon": "home"})
            items.append({"label": "/", "path": "/", "icon": "disk"})
            volumes = Path("/Volumes")
            if volumes.exists():
                try:
                    for entry in sorted(volumes.iterdir()):
                        if entry.is_dir():
                            items.append({"label": entry.name, "path": str(entry), "icon": "disk"})
                except OSError:
                    pass
        else:
            items.append({"label": "/", "path": "/", "icon": "disk"})

        return FSResult(ok=True, data={"favorites": items})

    # ------------------------------------------------------------------
    # get_policy / set_policy
    # ------------------------------------------------------------------
    def get_policy(self) -> FSResult:
        """Return the current policy configuration as JSON-serializable data."""
        return FSResult(ok=True, data={
            **self._policy_dict(),
            "copy_on_write_suffix": self._policy._suffix,
        })

    def set_policy(
        self,
        deny: list[str] | None = None,
        read: list[str] | None = None,
        read_execute: list[str] | None = None,
        write: list[str] | None = None,
        write_execute: list[str] | None = None,
        copy_on_write: list[str] | None = None,
    ) -> FSResult:
        """Replace the active policy.

        Each list defaults to ``[]`` when omitted or ``null``.
        The confirm callback is reset to the default :func:`AskConfirmation`.
        """
        self._policy = Policy(
            deny=deny,
            read=read,
            read_execute=read_execute,
            write=write,
            write_execute=write_execute,
            copy_on_write=copy_on_write,
        )
        return FSResult(ok=True, data=self._policy_dict())

    # ------------------------------------------------------------------
    # file_info
    # ------------------------------------------------------------------
    @_fs_op
    def file_info(self, path: str) -> FSResult:
        """Return metadata about *path*."""
        if err := self._check(path, "file_info"):
            return err
        p = Path(path).resolve()
        s = p.stat()
        return FSResult(ok=True, data={
            "path": str(p),
            "exists": p.exists(),
            "type": "dir" if p.is_dir() else "file",
            "size": s.st_size,
            "created": _ts_iso(s.st_ctime),
            "modified": _ts_iso(s.st_mtime),
            "readable": os.access(p, os.R_OK),
            "writable": os.access(p, os.W_OK),
        })

    # ------------------------------------------------------------------
    # touch_file
    # ------------------------------------------------------------------
    @_fs_op
    def touch_file(self, path: str) -> FSResult:
        """Create *path* if it does not exist, or update its modification time."""
        if err := self._check(path, "write_file"):
            return err
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch()
        return FSResult(ok=True, data={"path": str(p.resolve())})

    # ------------------------------------------------------------------
    # exec_file
    # ------------------------------------------------------------------
    @_fs_op
    def exec_file(
        self,
        path: str,
        args: list[str] | None = None,
        cwd: str | None = None,
        timeout: int = 30,
    ) -> FSResult:
        """Execute the program at *path* and return its output.

        The executable must reside in a folder granted ``read_execute`` or
        ``write_execute`` rights; all other policy rights deny execution.
        *path* must be absolute — relative paths are rejected to prevent
        ambiguous policy checks.

        Returns stdout, stderr, and the exit code.  A non-zero exit code is
        still reported as ``ok=True`` (the execution itself succeeded); the
        caller can inspect ``returncode`` to distinguish success from failure.

        The process is tracked in the module-level registry so that
        ``terminate_all_procs()`` can kill it if the tunnel shuts down while
        the process is still running.
        """
        p = Path(path)
        if not p.is_absolute():
            return FSResult(ok=False, error="exec_file requires an absolute path")

        if err := self._check(str(p), "exec_file"):
            return err

        proc = subprocess.Popen(
            [str(p)] + list(args or []),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
        )
        _register_proc(proc)
        try:
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                return FSResult(ok=False, error=f"Process timed out after {timeout}s")
        finally:
            _unregister_proc(proc)

        return FSResult(ok=True, data={
            "path":       str(p),
            "returncode": proc.returncode,
            "stdout":     stdout,
            "stderr":     stderr,
        })
