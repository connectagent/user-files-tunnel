"""
policy.py — access-control policy for LocalFileSystem operations.

Each directory is assigned one of four access rights:

    Deny          — all operations are denied; the confirmation callback is NOT invoked.
    Read          — read operations are allowed; write operations are denied without
                    invoking the callback.
    Write         — all operations are allowed; the confirmation callback is NOT invoked.
    WriteOnCopy   — all operations are allowed; writes are transparently redirected to
                    a file named ``{stem}[Agent's Copy]{suffix}`` so originals are
                    never modified.  Reads prefer the copy when it exists.

Resolution order (first match wins):
    1. Deny
    2. WriteOnCopy
    3. Read
    4. Write
    5. Neither — AskConfirmation (or a custom callback) is called.

Usage example::

    from policy import Policy

    policy = Policy(
        deny=["/etc", "/root"],
        read=["/home/user/docs"],
        write=["/home/user/projects"],
        copy_on_write=["/home/user/workspace"],
    )
    fs = LocalFileSystem(policy=policy)

To plug in a real confirmation UI, pass a callback::

    policy = Policy(write=[...], confirm=lambda path, op: "Allow")
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

# "Allow" or "Deny"
PolicyDecision = str

# Operations that modify the file system — used to enforce Read access.
_WRITE_OPS: frozenset[str] = frozenset({
    "write_file",
    "edit_file",
    "delete_file",
    "create_directory",
    "move_file",
})

# Operations that launch a subprocess — only allowed by execute rights.
_EXECUTE_OPS: frozenset[str] = frozenset({"exec_file"})


def AskConfirmation(path: str, operation: str) -> PolicyDecision:
    """Confirmation callback invoked when *path* matches no configured directory.

    Replace this function, or pass a custom callable to ``Policy(confirm=...)``,
    to implement interactive or rule-based confirmation.

    The default implementation unconditionally allows access.
    """
    return "Allow"


class Policy:
    """Controls which paths LocalFileSystem may access.

    Parameters
    ----------
    deny:
        Directories that are always denied for all operations.
        Takes highest priority.
    read:
        Directories where only read operations are allowed.
        Write operations (write_file, edit_file, delete_file,
        create_directory, move_file) are denied without invoking the callback.
    write:
        Directories where all operations are unconditionally allowed.
    copy_on_write:
        Directories where write operations are transparently redirected to a
        file named ``{stem}[Agent's Copy]{suffix}`` instead of modifying the
        original.  Read operations prefer the copy when it exists.
    confirm:
        Called when a path matches no configured directory.  Receives the
        resolved absolute path string and the operation name; must return
        ``"Allow"`` or ``"Deny"``.  Defaults to :func:`AskConfirmation`.
    """

    _VALID_RIGHTS = {"deny", "read", "read_execute", "write", "write_execute", "copy_on_write"}

    DEFAULT_SUFFIX = "[Agent's Copy]"

    @classmethod
    def from_file(cls, path: str, **kwargs) -> "Policy":
        """Load a policy from a JSON file.

        Format — an array of ``{"path": "...", "rights": "..."}`` objects,
        with an optional top-level ``"copy_on_write_suffix"`` string::

            [
              { "path": "C:/Windows",             "rights": "deny" },
              { "path": "C:/Users/Max/Documents",  "rights": "read" },
              { "path": "C:/Users/Max/Projects",   "rights": "write" },
              { "path": "C:/Users/Max/workspace",  "rights": "copy_on_write" }
            ]

        Or with a custom suffix::

            {
              "copy_on_write_suffix": "[My Copy]",
              "rules": [
                { "path": "C:/Users/Max/workspace", "rights": "copy_on_write" }
              ]
            }
        """
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        # Support both plain array and {"copy_on_write_suffix": ..., "rules": [...]}
        if isinstance(raw, dict):
            suffix = raw.get("copy_on_write_suffix", cls.DEFAULT_SUFFIX)
            rules = raw.get("rules", [])
        else:
            suffix = cls.DEFAULT_SUFFIX
            rules = raw
        if not isinstance(rules, list):
            raise ValueError("Policy file must contain a JSON array or {rules: [...]} object")
        deny, read, read_execute, write, write_execute, cow = [], [], [], [], [], []
        for entry in rules:
            folder = entry.get("path", "").strip()
            right  = entry.get("rights", "").strip()
            if not folder:
                raise ValueError(f"Missing 'path' in policy entry: {entry!r}")
            if right not in cls._VALID_RIGHTS:
                raise ValueError(
                    f"Unknown rights {right!r} in {entry!r}. "
                    f"Valid rights: {', '.join(sorted(cls._VALID_RIGHTS))}"
                )
            {
                "deny": deny, "read": read, "read_execute": read_execute,
                "write": write, "write_execute": write_execute, "copy_on_write": cow,
            }[right].append(folder)
        return cls(deny=deny, read=read, read_execute=read_execute,
                   write=write, write_execute=write_execute, copy_on_write=cow,
                   copy_on_write_suffix=suffix, **kwargs)

    def __init__(
        self,
        deny: list[str] | None = None,
        read: list[str] | None = None,
        read_execute: list[str] | None = None,
        write: list[str] | None = None,
        write_execute: list[str] | None = None,
        copy_on_write: list[str] | None = None,
        copy_on_write_suffix: str = DEFAULT_SUFFIX,
        confirm: Callable[[str, str], PolicyDecision] = AskConfirmation,
    ):
        # Resolve all configured directories to absolute canonical paths once,
        # so comparisons against resolved operation paths are always valid.
        self._deny          = [Path(p).resolve() for p in (deny          or [])]
        self._read          = [Path(p).resolve() for p in (read          or [])]
        self._read_execute  = [Path(p).resolve() for p in (read_execute  or [])]
        self._write         = [Path(p).resolve() for p in (write         or [])]
        self._write_execute = [Path(p).resolve() for p in (write_execute or [])]
        self._copy_on_write = [Path(p).resolve() for p in (copy_on_write or [])]
        self._suffix  = copy_on_write_suffix
        self._confirm = confirm

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_under(path: Path, folder: Path) -> bool:
        """Return ``True`` when *path* is *folder* itself or a descendant of it."""
        try:
            path.relative_to(folder)
            return True
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def copy_path(self, path: str) -> str:
        """Return the Agent's Copy path for *path* if it falls under a
        copy_on_write directory, otherwise return *path* unchanged.

        ``/woc/file.txt``                        → ``/woc/file[Agent's Copy].txt``
        ``/woc/notes``                           → ``/woc/notes[Agent's Copy]``
        ``/woc/sub[Agent's Copy]/file.txt``      → ``/woc/sub[Agent's Copy]/file.txt``  (already inside a copy dir)
        ``/other/file.txt``                      → ``/other/file.txt``  (unaffected)
        """
        p = Path(path).resolve()
        for folder in self._copy_on_write:
            if self._is_under(p, folder):
                # If already inside a copy directory, treat as full write — no redirect.
                relative = p.relative_to(folder)
                if any(self._suffix in part for part in relative.parts):
                    return path
                return str(p.parent / f"{p.stem}{self._suffix}{p.suffix}")
        return path

    def check(self, path: str, operation: str = "") -> PolicyDecision:
        """Decide whether *operation* on *path* is permitted.

        Parameters
        ----------
        path:
            The file-system path being accessed (need not exist yet).
        operation:
            Name of the operation (e.g. ``"read_file"``), used to distinguish
            read vs. write for the Read access right, and forwarded to the
            confirmation callback for context.

        Returns
        -------
        ``"Allow"`` or ``"Deny"``.

        Resolution strategy
        -------------------
        The **most specific** (deepest) matching folder wins, regardless of
        rule category.  This allows a ``copy_on_write`` rule on a subfolder to
        override a ``deny`` rule on a parent (e.g. deny ``C:\\`` but grant
        copy_on_write access to ``C:\\Users\\Max\\Documents``).
        When two rules match at the same depth the priority order
        deny > read_execute > copy_on_write > read > write_execute > write
        breaks the tie.

        Execute permission matrix
        -------------------------
        read_execute  — reads allowed, execute allowed, writes denied.
        write_execute — reads allowed, writes allowed, execute allowed.
        read          — reads allowed, execute denied, writes denied.
        write         — reads and writes allowed, execute denied.
        copy_on_write — reads and writes-to-copy allowed, execute denied.
        deny          — everything denied.
        """
        p = Path(path).resolve()
        is_write   = operation in _WRITE_OPS
        is_execute = operation in _EXECUTE_OPS

        # Walk all rule categories in priority order; track the deepest match.
        # Strictly-greater depth check means earlier (higher-priority) categories
        # win ties, preserving the priority ordering documented above.
        best_right: str | None = None
        best_depth = -1

        for right_name, folders in (
            ("deny",          self._deny),
            ("read_execute",  self._read_execute),
            ("copy_on_write", self._copy_on_write),
            ("read",          self._read),
            ("write_execute", self._write_execute),
            ("write",         self._write),
        ):
            for folder in folders:
                if self._is_under(p, folder):
                    depth = len(folder.parts)
                    if depth > best_depth:
                        best_depth = depth
                        best_right = right_name

        if best_right == "deny":
            return "Deny"
        if best_right == "read_execute":
            return "Deny" if is_write else "Allow"   # reads + exec allowed; writes denied
        if best_right == "copy_on_write":
            return "Deny" if is_execute else "Allow"  # exec denied; writes redirected to copy
        if best_right == "read":
            return "Deny" if (is_write or is_execute) else "Allow"
        if best_right == "write_execute":
            return "Allow"
        if best_right == "write":
            return "Deny" if is_execute else "Allow"  # exec denied

        # No rule matched — let the callback decide.
        return self._confirm(str(p), operation)
