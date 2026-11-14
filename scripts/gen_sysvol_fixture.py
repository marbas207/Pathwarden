"""Generates testdata/sysvol (run from the repo root: python scripts/gen_sysvol_fixture.py).

SYS.LOCAL, with what Pathwarden's built-in collector reads from SYSVOL and
NETLOGON (pathwarden-sysvol.json, see crates/pathwarden-core/src/sysvol):
- DEFAULT DOMAIN POLICY (linked to the domain, so Tier Zero): BOB has Modify on
  its SYSVOL folder but no right on the GPO in AD -> WriteGPOFiles, PW-003,
  PW-027 (high).
- WALLPAPER (linked to OU WORKSTATIONS): WALLADMIN may edit it in AD and has
  Modify on its folder (consistent: no edge); EVE owns its Machine subfolder
  (no AD right) -> WriteGPOFiles, PW-027 (medium). Its Groups.xml holds a
  cpassword for SYS\\svc_backup -> PW-026.
- ALICE (Domain Admin) runs admin.bat from NETLOGON; DAVE can write it ->
  WriteLogonScript, PW-003. CAROL's users\\logon.bat is read-only for everyone
  but admins -> nothing.
- Default writers (SYSTEM, CREATOR OWNER, Domain Admins, Administrators) are on
  every descriptor and never reported.
"""
import json
import os
import struct

D = "S-1-5-21-7000-7000-7000"
DN = "SYS.LOCAL"
OUT = "testdata/sysvol"
STAMP = "20261001020000"
DDP = "31B2F340-016D-11D2-945F-00C04FB984F9"
WALL = "BBBB0000-0000-0000-0000-000000000002"
WALL_CN = "{5D1B8E2C-0F7A-4E4B-9C1D-2B3A4C5D6E7F}"

FULL = 0x1F01FF
MODIFY = 0x1301BF
READ = 0x1200A9
GENERIC_ALL = 0x10000000


def sid(rid):
    return f"{D}-{rid}"


def sid_bytes(s):
    parts = [int(p) for p in s[2:].split("-")]
    out = bytes([parts[0], len(parts) - 2]) + parts[1].to_bytes(6, "big")
    for sub in parts[2:]:
        out += struct.pack("<I", sub)
    return out


def sd(owner, aces):
    """Self-relative security descriptor, hex. aces: (type, flags, mask, sid)."""
    body = b""
    for kind, flags, mask, s in aces:
        sb = sid_bytes(s)
        body += struct.pack("<BBHI", kind, flags, 8 + len(sb), mask) + sb
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(body), len(aces), 0) + body
    ob = sid_bytes(owner)
    header = struct.pack("<BBHIIII", 1, 0, 0x8004, 20, 0, 0, 20 + len(ob))
    return (header + ob + acl).hex()


DEFAULTS = [
    (0, 0, FULL, sid(512)),
    (0, 0, FULL, "S-1-5-18"),
    (0, 0x0B, GENERIC_ALL, "S-1-3-0"),
    (0, 0, READ, "S-1-5-11"),
    (0, 0, FULL, "S-1-5-32-544"),
]


def ref(i, t):
    return {"ObjectIdentifier": i, "ObjectType": t}


def ace(p, t, right):
    return {"PrincipalSID": p, "PrincipalType": t, "RightName": right, "IsInherited": False}


def props(label, **kw):
    return {"name": f"{label}@{DN}", "domain": DN, "domainsid": D} | kw


def write(kind, data):
    with open(os.path.join(OUT, f"{STAMP}_{kind}.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"data": data, "meta": {"methods": 0, "type": kind, "count": len(data), "version": 6}}, f, indent=2)
        f.write("\n")


def user(rid, name, **kw):
    return {"ObjectIdentifier": sid(rid), "PrimaryGroupSID": sid(513),
            "Properties": props(name, enabled=True, **kw), "Aces": []}


os.makedirs(OUT, exist_ok=True)
write("domains", [{"ObjectIdentifier": D, "Properties": props("X", name=DN),
                   "Links": [{"IsEnforced": False, "GUID": DDP}], "Aces": [], "Trusts": []}])
write("ous", [{"ObjectIdentifier": "CCCC0000-0000-0000-0000-000000000003",
               "Properties": props("WORKSTATIONS", distinguishedname="OU=WORKSTATIONS,DC=SYS,DC=LOCAL"),
               "Links": [{"IsEnforced": False, "GUID": WALL}], "ChildObjects": [], "Aces": []}])
write("gpos", [
    {"ObjectIdentifier": DDP, "Properties": props("DEFAULT DOMAIN POLICY"),
     "Aces": [ace(sid(512), "Group", "GenericAll")], "IsDeleted": False},
    {"ObjectIdentifier": WALL, "Properties": props("WALLPAPER"),
     "Aces": [ace(sid(512), "Group", "GenericAll"), ace(sid(1105), "User", "GenericWrite")], "IsDeleted": False},
])
write("users", [
    user(500, "ADMINISTRATOR", admincount=True),
    user(1101, "ALICE", admincount=True, logonscript="admin.bat"),
    user(1102, "BOB"),
    user(1103, "CAROL", logonscript="users\\logon.bat"),
    user(1104, "DAVE"),
    user(1105, "WALLADMIN"),
    user(1106, "EVE"),
    user(1107, "SVC_BACKUP"),
])
write("groups", [
    {"ObjectIdentifier": sid(512), "Properties": props("DOMAIN ADMINS", admincount=True),
     "Members": [ref(sid(500), "User"), ref(sid(1101), "User")], "Aces": []},
    {"ObjectIdentifier": sid(513), "Properties": props("DOMAIN USERS"), "Members": [], "Aces": []},
])

sidecar = {
    "schema": "pathwarden.sysvol.v1",
    "domain": "sys.local",
    "dc": "dc01.sys.local",
    "checks": {
        "gpo_acl": {"status": "complete", "read": 4},
        "logon_script_acl": {"status": "complete", "read": 2},
        "gpp": {"status": "complete", "read": 1},
    },
    "gpos": [
        {"guid": "{" + DDP + "}", "object_id": DDP, "folders": [
            {"path": "", "sd": sd(sid(512), DEFAULTS + [(0, 0, MODIFY, sid(1102))])},
            {"path": "Machine", "sd": sd(sid(512), [(a, f | 0x10, m, s) for a, f, m, s in DEFAULTS]
                                         + [(0, 0x10, MODIFY, sid(1102))])},
        ]},
        {"guid": WALL_CN, "object_id": WALL, "folders": [
            {"path": "", "sd": sd(sid(1105), DEFAULTS + [(0, 0, MODIFY, sid(1105))])},
            {"path": "Machine", "sd": sd(sid(1106), DEFAULTS)},
        ]},
    ],
    "logon_scripts": [
        {"script": "admin.bat", "users": [sid(1101)],
         "sd": sd("S-1-5-32-544", DEFAULTS + [(0, 0, 0x6, sid(1104))])},
        {"script": "users\\logon.bat", "users": [sid(1103)], "sd": sd("S-1-5-32-544", DEFAULTS)},
    ],
    "gpp_passwords": [
        {"guid": WALL_CN, "object_id": WALL, "file": "Machine\\Preferences\\Groups\\Groups.xml",
         "accounts": ["SYS\\svc_backup"]},
    ],
}
with open(os.path.join(OUT, f"{STAMP}_pathwarden-sysvol.json"), "w", encoding="utf-8", newline="\n") as f:
    json.dump(sidecar, f, indent=2)
    f.write("\n")
