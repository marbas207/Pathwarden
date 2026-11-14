"""Generates testdata/sdprop (run from the repo root: python scripts/gen_sdprop_fixture.py).

SDP.LOCAL, modeled on what the GOAD lab showed in real collector output:
- MALLORY has GenericAll on AdminSDHolder; SDProp has copied that ACE onto the
  protected DA account EVE and the Domain Admins group (adminCount=1).
- BOB has GenericWrite and WriteDacl on the domain controller DC01 (computers
  are not protected by SDProp).
Files carry a SharpHound-style timestamp so the collection time is known.
"""
import json
import os

D = "S-1-5-21-6000-6000-6000"
DN = "SDP.LOCAL"
OUT = "testdata/sdprop"
STAMP = "20240410083609"
ADMINSDHOLDER = "77777777-0000-0000-0000-000000000001"


def sid(rid):
    return f"{D}-{rid}"


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


os.makedirs(OUT, exist_ok=True)
copied = ace(sid(1102), "User", "GenericAll")

write("domains", [{"ObjectIdentifier": D, "Properties": props("X", name=DN), "Aces": [], "Trusts": []}])
write("users", [
    {"ObjectIdentifier": sid(500), "PrimaryGroupSID": sid(513), "Properties": props("ADMINISTRATOR", enabled=True, admincount=True), "Aces": [copied]},
    {"ObjectIdentifier": sid(1101), "PrimaryGroupSID": sid(513), "Properties": props("EVE", enabled=True, admincount=True), "Aces": [copied]},
    {"ObjectIdentifier": sid(1102), "PrimaryGroupSID": sid(513), "Properties": props("MALLORY", enabled=True), "Aces": []},
    {"ObjectIdentifier": sid(1103), "PrimaryGroupSID": sid(513), "Properties": props("BOB", enabled=True), "Aces": []},
])
write("groups", [
    {"ObjectIdentifier": sid(512), "Properties": props("DOMAIN ADMINS", admincount=True),
     "Members": [ref(sid(500), "User"), ref(sid(1101), "User")], "Aces": [copied]},
    {"ObjectIdentifier": sid(513), "Properties": props("DOMAIN USERS"), "Members": [], "Aces": []},
])
write("computers", [
    {"ObjectIdentifier": sid(1000), "PrimaryGroupSID": sid(516), "IsDC": True,
     "Properties": props("DC01", name=f"DC01.{DN}", enabled=True),
     "Aces": [ace(sid(1103), "User", "GenericWrite"), ace(sid(1103), "User", "WriteDacl")]},
])
write("containers", [
    {"ObjectIdentifier": ADMINSDHOLDER,
     "Properties": props("ADMINSDHOLDER", distinguishedname=f"CN=ADMINSDHOLDER,CN=SYSTEM,DC=SDP,DC=LOCAL"),
     "Aces": [copied]},
])
print("ok")
