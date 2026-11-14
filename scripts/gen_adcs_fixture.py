"""Generates testdata/adcs (run from the repo root: python scripts/gen_adcs_fixture.py): PKI.LOCAL with one vulnerable template per ESC.

CA1 (PKI-CA) is eligible: enabled host CA01, self-signed root R1 for the domain,
and listed in the NTAuth store. CA2 (ROGUE-CA) chains to its own root but is NOT
in NTAuth, so nothing published there is exploitable for domain logon.
"""
import json
import os

D = "S-1-5-21-5000-5000-5000"
DN = "PKI.LOCAL"
OUT = "testdata/adcs"
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
AGENT = "1.3.6.1.4.1.311.20.2.1"


def sid(rid):
    return f"{D}-{rid}"


def ref(i, t):
    return {"ObjectIdentifier": i, "ObjectType": t}


def ace(p, t, right, inherited=False):
    return {"PrincipalSID": p, "PrincipalType": t, "RightName": right, "IsInherited": inherited}


def props(label, **kw):
    return {"name": f"{label}@{DN}", "domain": DN, "domainsid": D} | kw


def write(kind, data):
    path = os.path.join(OUT, f"pki_{kind}.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"data": data, "meta": {"methods": 0, "type": kind, "count": len(data), "version": 6}}, f, indent=2)
        f.write("\n")


os.makedirs(OUT, exist_ok=True)
AU = f"{DN}-S-1-5-11"

write("domains", [{"ObjectIdentifier": D, "Properties": props("X", name=DN), "Aces": [], "Trusts": []}])

users = {"ALICE": 1101, "BOB": 1102, "CAROL": 1103, "DAVE": 1104, "EVE": 1105, "FRANK": 1106}
user_objs = []
for name, rid in users.items():
    o = {"ObjectIdentifier": sid(rid), "PrimaryGroupSID": sid(513), "Properties": props(name, enabled=True), "Aces": []}
    if name == "DAVE":
        # ESC9a: CAROL can rewrite DAVE's UPN.
        o["Aces"].append(ace(sid(1103), "User", "GenericWrite"))
    user_objs.append(o)
write("users", user_objs)

write("groups", [
    {"ObjectIdentifier": sid(512), "Properties": props("DOMAIN ADMINS"), "Members": [ref(sid(1105), "User")]},
    {"ObjectIdentifier": sid(513), "Properties": props("DOMAIN USERS"), "Members": []},
    {"ObjectIdentifier": sid(1150), "Properties": props("WEBADMINS"), "Members": [ref(sid(1102), "User")]},
    {"ObjectIdentifier": sid(1151), "Properties": props("AGENTS"), "Members": [ref(sid(1101), "User")]},
    {"ObjectIdentifier": sid(1152), "Properties": props("SQL OPERATORS"), "Members": []},
])

write("computers", [
    {"ObjectIdentifier": sid(1000), "PrimaryGroupSID": sid(516), "IsDC": True,
     "Properties": props("DC01", name=f"DC01.{DN}", enabled=True),
     # Compatibility mode (1) still allows weak mappings; Schannel without UPN mapping.
     "DCRegistryData": {"CertificateMappingMethods": {"Value": 24, "Collected": True},
                        "StrongCertificateBindingEnforcement": {"Value": 1, "Collected": True}}},
    {"ObjectIdentifier": sid(1001), "PrimaryGroupSID": sid(515), "Properties": props("CA01", name=f"CA01.{DN}", enabled=True)},
    {"ObjectIdentifier": sid(1002), "PrimaryGroupSID": sid(515), "Properties": props("CA02", name=f"CA02.{DN}", enabled=True)},
])


def template(guid, name, enroll, extra_aces=(), **kw):
    p = props(name, requiresmanagerapproval=False, schemaversion=2, authorizedsignatures=0,
              enrolleesuppliessubject=False, nosecurityextension=False, effectiveekus=[CLIENT_AUTH],
              authenticationenabled=True, certificatepolicy=[], applicationpolicies=[])
    p.update(kw)
    return {"ObjectIdentifier": guid, "Properties": p,
            "Aces": [ace(s, t, "Enroll") for s, t in enroll] + list(extra_aces)}


T_ESC1 = "11111111-0000-0000-0000-000000000001"
T_USER = "11111111-0000-0000-0000-000000000002"
T_AGENT = "11111111-0000-0000-0000-000000000003"
T_NOSEC = "11111111-0000-0000-0000-000000000004"
T_POLICY = "11111111-0000-0000-0000-000000000005"
T_SAFE = "11111111-0000-0000-0000-000000000006"
write("certtemplates", [
    template(T_ESC1, "VULNWEB", [(sid(1150), "Group")], enrolleesuppliessubject=True),
    # Schema 1 user template: the ESC3 target. BOB can rewrite it (ESC4).
    template(T_USER, "USER", [(sid(513), "Group")], [ace(sid(1102), "User", "WriteDacl")], schemaversion=1),
    template(T_AGENT, "ENROLLMENTAGENT", [(sid(1151), "Group")], effectiveekus=[AGENT], authenticationenabled=False),
    template(T_NOSEC, "NOSECEXT", [(sid(513), "Group")], nosecurityextension=True, subjectaltrequireupn=True),
    template(T_POLICY, "POLICYCERT", [(sid(1101), "User")], certificatepolicy=["1.2.3.4.5.6"]),
    # Supplies subject but needs manager approval: not ESC1.
    template(T_SAFE, "APPROVED", [(AU, "Group")], enrolleesuppliessubject=True, requiresmanagerapproval=True),
])

write("issuancepolicies", [
    {"ObjectIdentifier": "22222222-0000-0000-0000-000000000001",
     "Properties": props("HIGH ASSURANCE", certtemplateoid="1.2.3.4.5.6"),
     "GroupLink": ref(sid(512), "Group")},
])

CA1 = "33333333-0000-0000-0000-000000000001"
CA2 = "33333333-0000-0000-0000-000000000002"


def enterprise_ca(guid, name, host, thumb, templates, ca_security, san=False, endpoints=(), interface=None):
    # interface: the CA's InterfaceFlags as read by the built-in collector
    # (enforceencryptionforrequests); None when not read.
    extra = {} if interface is None else {"enforceencryptionforrequests": interface}
    return {
        "ObjectIdentifier": guid,
        "Properties": props(name, caname=name, dnshostname=f"{host}.{DN}".lower(), certthumbprint=thumb,
                            certchain=[thumb], casecuritycollected=True, enrollmentagentrestrictionscollected=True,
                            isuserspecifiessanenabledcollected=True, **extra),
        "HostingComputer": sid({"CA01": 1001, "CA02": 1002}[host]),
        "CARegistryData": {
            "CASecurity": {"Data": ca_security, "Collected": True, "FailureReason": None},
            "EnrollmentAgentRestrictions": {"Restrictions": [], "Collected": True, "FailureReason": None},
            "IsUserSpecifiesSanEnabled": {"Value": san, "Collected": True, "FailureReason": None},
        },
        "EnabledCertTemplates": [ref(t, "CertTemplate") for t in templates],
        "HttpEnrollmentEndpoints": list(endpoints),
        # LDAP ACEs: CA rights here are ignored because registry security was collected.
        "Aces": [ace(sid(1104), "User", "ManageCA")],
    }


write("enterprisecas", [
    enterprise_ca(CA1, "PKI-CA", "CA01", "AAAA", [T_ESC1, T_USER, T_AGENT, T_NOSEC, T_POLICY, T_SAFE], [
        ace(AU, "Group", "Enroll"),
        ace(sid(512), "Group", "ManageCA"),
        ace(sid(1106), "User", "ManageCA"),            # ESC7 via PW-003
        ace(f"{sid(1001)}-544", "LocalGroup", "ManageCA"),  # local groups are dropped
    ], san=True, endpoints=[
        {"Result": {"Url": "http://ca01.pki.local/certsrv/", "Type": "WebEnrollmentApplication",
                    "Status": "Vulnerable_NtlmHttpEndpoint", "ADCSWebEnrollmentHTTP": True,
                    "ADCSWebEnrollmentHTTPS": False, "ADCSWebEnrollmentEPA": False},
         "Collected": True, "FailureReason": None},
        {"Result": {"Url": "https://ca01.pki.local/certsrv/", "Type": "WebEnrollmentApplication",
                    "Status": "NotVulnerable_NtlmChannelBindingRequired", "ADCSWebEnrollmentHTTP": False,
                    "ADCSWebEnrollmentHTTPS": True, "ADCSWebEnrollmentEPA": True},
         "Collected": True, "FailureReason": None},
    ], interface=False),
    # Not trusted for NT auth, but its SAN flag is still worth a hygiene finding.
    enterprise_ca(CA2, "ROGUE-CA", "CA02", "BBBB", [T_ESC1], [ace(AU, "Group", "Enroll")], san=True),
])

write("rootcas", [
    {"ObjectIdentifier": "44444444-0000-0000-0000-000000000001", "DomainSID": D,
     "Properties": props("PKI-CA ROOT", certthumbprint="AAAA", certchain=["AAAA"])},
    {"ObjectIdentifier": "44444444-0000-0000-0000-000000000002", "DomainSID": D,
     "Properties": props("ROGUE ROOT", certthumbprint="BBBB", certchain=["BBBB"])},
])

write("ntauthstores", [
    {"ObjectIdentifier": "55555555-0000-0000-0000-000000000001", "DomainSID": D,
     "Properties": props("NTAUTHCERTIFICATES", certthumbprints=["AAAA"])},
])
print("ok")
