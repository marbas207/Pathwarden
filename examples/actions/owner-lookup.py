"""A Pathwarden finding action: say who owns the objects a finding is about,
from a CSV file of owners. It returns a message and sends nothing anywhere.
See owner-lookup.md beside it.

    [[action]]
    name = "owners"
    command = ["C:\\Program Files\\Python313\\python.exe", "C:\\Pathwarden\\actions\\owner-lookup.py"]
    owners_file = "C:\\Pathwarden\\actions\\owners.csv"   # default: owners.example.csv beside this script

The CSV has a header and three columns: `match`, a name pattern where *
stands for anything (SVC-*@SCALE.LOCAL); `owner`; and `contact`. The first
row that matches an object names its owner.
"""

from __future__ import annotations

import csv
import fnmatch
import os

import pathwarden_action as pw

ACTIONS = [
    {
        "id": "lookup",
        "label": "Find the owners",
        "description": "Says who owns the objects this finding is about.",
        "sends": "Nothing: it reads a file of owners on this computer.",
        "inputs": [
            {
                "id": "scope",
                "label": "Look up",
                "type": "choice",
                "choices": ["Affected objects", "Affected objects and the path"],
                "default": "Affected objects",
            }
        ],
    }
]


def owners(path: str):
    """The rows of the owners file: (pattern, owner, contact)."""
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
    except FileNotFoundError:
        raise pw.Failed(f"The owners file {path} isn't there. Set owners_file to a CSV with match, owner and contact.") from None
    out = []
    for i, row in enumerate(rows, start=2):
        if not row.get("match") or not row.get("owner"):
            pw.note(f"{path} line {i}: match or owner is empty; the line is skipped")
            continue
        out.append((row["match"].strip().upper(), row["owner"].strip(), (row.get("contact") or "").strip()))
    return out


def names(req: pw.Request):
    """The object names to look up, in order, each once."""
    f = req.finding
    found = [a.get("name") or a.get("id") for a in f.get("affected") or [] if isinstance(a, dict)]
    path = f.get("path") or {}
    if req.inputs.get("scope") == "Affected objects and the path" and isinstance(path, dict):
        found.append(path.get("source"))
        for step in path.get("steps") or []:
            found += [step.get("from"), step.get("to")]
        found.append(path.get("target"))
    seen, out = set(), []
    for n in found:
        if n and n.upper() not in seen:
            seen.add(n.upper())
            out.append(n)
    return out


def lookup(req: pw.Request):
    # It changes nothing, so a dry run does the same as a run.
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)), "owners.example.csv")
    path = req.setting("owners_file", default)
    table = owners(path)
    objects = names(req)
    if not objects:
        return pw.ok("This finding names no objects to look up.")
    pw.progress(f"Looking up {len(objects)} object{'' if len(objects) == 1 else 's'} in {os.path.basename(path)}")
    lines, unknown = [], []
    for name in objects[:50]:
        hit = next(((o, c) for m, o, c in table if fnmatch.fnmatchcase(name.upper(), m)), None)
        if hit:
            lines.append(f"{name}: {hit[0]}" + (f" ({hit[1]})" if hit[1] else ""))
        else:
            unknown.append(name)
    if unknown:
        lines.append("No owner on file: " + ", ".join(unknown[:20]) + (f" and {len(unknown) - 20} more" if len(unknown) > 20 else ""))
    if len(objects) > 50:
        lines.append(f"{len(objects) - 50} more objects weren't looked up.")
    return pw.ok("\n".join(lines))


if __name__ == "__main__":
    pw.main(ACTIONS, {"lookup": lookup})
