"""Signature data for the pickle x-ray.

This module is the SOLE location for concrete opcode / import classification data
(see CLAUDE.md description-discipline §5). Classifications are sourced from public
defensive scanners and reimplemented here over stdlib ``pickletools``; no
third-party code is vendored.

Sources (consulted for the published classifications only):
  - picklescan (MIT)    https://github.com/mmaitre314/picklescan
  - modelscan (Apache)  https://github.com/protectai/modelscan
  - modelaudit (MIT)    https://github.com/promptfoo/modelaudit

The lists below are intentionally conservative (high precision). Unknown imports
are reported at a lower severity rather than asserted safe.
"""

from __future__ import annotations

# Opcodes (pickle VM mnemonics, per CPython pickletools) that carry a
# module/attribute reference, i.e. resolve an external symbol during unpickling.
IMPORT_BEARING_OPCODES = frozenset({"GLOBAL", "STACK_GLOBAL"})

# Opcodes that reconstruct objects / invoke a resolved callable during unpickling.
RECONSTRUCT_OPCODES = frozenset({"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"})

# (module, attribute) pairs flagged dangerous by the public scanners above.
# A reference to any of these inside a model artifact is treated as FAIL.
_DANGEROUS_PAIRS = frozenset(
    {
        ("os", "system"),
        ("os", "popen"),
        ("os", "execv"),
        ("os", "execve"),
        ("os", "spawnl"),
        ("os", "spawnv"),
        ("posix", "system"),
        ("nt", "system"),
        ("subprocess", "Popen"),
        ("subprocess", "call"),
        ("subprocess", "run"),
        ("subprocess", "check_output"),
        ("builtins", "eval"),
        ("builtins", "exec"),
        ("builtins", "compile"),
        ("builtins", "__import__"),
        ("builtins", "getattr"),
        ("importlib", "import_module"),
        ("pty", "spawn"),
        ("runpy", "_run_code"),
        ("webbrowser", "open"),
    }
)

# Whole modules whose any attribute is dangerous in a deserialized-data context.
_DANGEROUS_MODULES = frozenset(
    {
        "socket",
        "ctypes",
        "shutil",
        "code",
        "commands",
    }
)


def classify_import(module: str, attr: str) -> tuple[str, int] | None:
    """Classify a referenced symbol.

    Returns (reason, severity_int) where severity_int maps to Severity, or None
    if the symbol is not on any denylist. severity 2 = FAIL, 1 = WARN.
    """
    mod = (module or "").split(".")[0]
    if (mod, attr) in _DANGEROUS_PAIRS:
        return ("references a known code-execution sink", 2)
    if mod in _DANGEROUS_MODULES:
        return ("references a module flagged in deserialization contexts", 2)
    return None
