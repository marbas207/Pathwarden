"""Writes the hand-made MSSQLHound and ConfigManBearPig fixtures.

Shapes follow the tools' real output (MSSQLHound 92efaeb sample_data,
ConfigManBearPig 231575a sample_data): IDs, kinds, property names, edge
properties (traversable, collectionSource, assumed, help text), metadata
placement. Run from the repository root:

    python -I scripts/gen_opengraph_fixtures.py testdata/opengraph
"""
import json, os, sys

OUT = sys.argv[1]
D = "S-1-5-21-3000-3000-3000"
HELP = {"general": "Help text as the collector writes it.", "windowsAbuse": "...", "linuxAbuse": "...",
        "opsec": "...", "references": "https://example.invalid/"}


def edge(kind, start, end, **props):
    p = {"traversable": True}
    p.update(HELP)
    p.update(props)
    return {"kind": kind, "start": {"value": start, "match_by": "id"}, "end": {"value": end, "match_by": "id"},
            "properties": p}


def node(id_, kind, **props):
    return {"id": id_, "kinds": [kind] if isinstance(kind, str) else kind, "properties": props}


def write(path, doc, metadata_last=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if metadata_last:
        meta = doc.pop("metadata", None)
        doc = {"graph": doc["graph"]}
        if meta:
            doc["metadata"] = meta
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


# ---------------------------------------------------------------- MSSQLHound
S = f"{D}-1002:1433"    # WS01, runs as SVC_BACKUP (Domain Admin)
S2 = f"{D}-1001:1433"   # APP01
S3 = f"{D}-1001:1434"   # APP01, second instance
nodes = [
    node(S, "MSSQL_Server", name="ws01.corp.local:1433", instanceName="MSSQLSERVER", port=1433,
         serviceAccount="CORP\\svc_backup", extendedProtection="Off", isMixedModeAuthEnabled=True,
         domainPrincipalsWithSysadmin=[f"CORP\\alice@{S}", f"CORP\\carol@{S}"]),
    node(f"CORP\\alice@{S}", "MSSQL_Login", name="CORP\\alice", type="WINDOWS_LOGIN", disabled=False,
         isActiveDirectoryPrincipal=True, memberOfRoles=["sysadmin", "public"], explicitPermissions=["CONNECT SQL"]),
    # DENY CONTROL SERVER on dave (listed, but no MSSQL_ControlServer edge of
    # its own), while a role he is in grants it.
    node(f"CORP\\dave@{S}", "MSSQL_Login", name="CORP\\dave", type="WINDOWS_LOGIN", disabled=False,
         isActiveDirectoryPrincipal=True, memberOfRoles=["opsrole", "public"],
         explicitPermissions=["CONNECT SQL", "CONTROL SERVER"]),
    node(f"CORP\\carol@{S}", "MSSQL_Login", name="CORP\\carol", type="WINDOWS_LOGIN", disabled=True,
         isActiveDirectoryPrincipal=True, memberOfRoles=["sysadmin", "public"]),
    node(f"dbowner@{S}", "MSSQL_Login", name="dbowner", type="SQL_LOGIN", disabled=False,
         memberOfRoles=["public"], explicitPermissions=["CONNECT SQL"]),
    node(f"sysadmin@{S}", "MSSQL_ServerRole", name="sysadmin", isFixedRole=True, explicitPermissions=["CONTROL SERVER"],
         members=["CORP\\alice", "CORP\\carol"]),
    node(f"public@{S}", "MSSQL_ServerRole", name="public", isFixedRole=False),
    node(f"opsrole@{S}", "MSSQL_ServerRole", name="opsrole", isFixedRole=False, explicitPermissions=["CONTROL SERVER"]),
    node(f"{S}\\AppDB", "MSSQL_Database", name="AppDB", isTrustworthy=True, ownerLoginName="dbowner",
         OwnerObjectIdentifier=f"dbowner@{S}"),
    node(f"{S}\\OpsDB", "MSSQL_Database", name="OpsDB", isTrustworthy=True, ownerLoginName="CORP\\alice",
         OwnerObjectIdentifier=f"CORP\\alice@{S}"),
    # APP01:1433: every login can impersonate svc_app (a sysadmin) through public.
    node(S2, "MSSQL_Server", name="app01.corp.local:1433", instanceName="MSSQLSERVER", port=1433),
    node(f"CORP\\bob@{S2}", "MSSQL_Login", name="CORP\\bob", type="WINDOWS_LOGIN", disabled=False,
         isActiveDirectoryPrincipal=True, memberOfRoles=["public"]),
    node(f"CORP\\dave@{S2}", "MSSQL_Login", name="CORP\\dave", type="WINDOWS_LOGIN", disabled=False,
         isActiveDirectoryPrincipal=True, memberOfRoles=["public"],
         explicitPermissions=["CONNECT SQL", "IMPERSONATE ANY LOGIN"]),
    node(f"svc_app@{S2}", "MSSQL_Login", name="svc_app", type="SQL_LOGIN", disabled=False,
         memberOfRoles=["sysadmin", "public"]),
    node(f"sysadmin@{S2}", "MSSQL_ServerRole", name="sysadmin", isFixedRole=True),
    node(f"public@{S2}", "MSSQL_ServerRole", name="public", isFixedRole=False),
    # APP01:1434: its only administrator login is disabled.
    node(S3, "MSSQL_Server", name="app01.corp.local:1434", instanceName="REPORTS", port=1434),
    node(f"CORP\\carol@{S3}", "MSSQL_Login", name="CORP\\carol", type="WINDOWS_LOGIN", disabled=True,
         isActiveDirectoryPrincipal=True, memberOfRoles=["sysadmin"]),
    node(f"sysadmin@{S3}", "MSSQL_ServerRole", name="sysadmin", isFixedRole=True),
    # AD stubs, as MSSQLHound writes them (they never change the AD data).
    node(f"{D}-1201", ["User", "Base"], name="svc_backup", SAMAccountName="svc_backup", isEnabled=True),
]
linked = dict(dataAccess=True, rpcOut=True, provider="SQLNCLI", product="", localLogin="All Logins",
              remoteIsSysadmin=True, remoteIsSecurityAdmin=False, remoteHasControlServer=True,
              remoteHasImpersonateAnyLogin=False, remoteIsMixedMode=True)
edges = [
    edge("MSSQL_HasLogin", f"{D}-1101", f"CORP\\alice@{S}"),
    edge("MSSQL_HasLogin", f"{D}-1104", f"CORP\\dave@{S}"),
    edge("MSSQL_HasLogin", f"{D}-1103", f"CORP\\carol@{S}"),
    edge("MSSQL_MemberOf", f"CORP\\alice@{S}", f"sysadmin@{S}"),
    edge("MSSQL_MemberOf", f"CORP\\alice@{S}", f"public@{S}"),
    edge("MSSQL_MemberOf", f"CORP\\carol@{S}", f"sysadmin@{S}"),
    edge("MSSQL_MemberOf", f"CORP\\dave@{S}", f"opsrole@{S}"),
    edge("MSSQL_ControlServer", f"sysadmin@{S}", S),
    edge("MSSQL_ControlServer", f"opsrole@{S}", S),
    edge("MSSQL_Contains", S, f"{S}\\AppDB"),
    edge("MSSQL_Contains", S, f"{S}\\OpsDB"),
    edge("MSSQL_Owns", f"dbowner@{S}", f"{S}\\AppDB"),
    edge("MSSQL_Owns", f"CORP\\alice@{S}", f"{S}\\OpsDB"),
    edge("MSSQL_ExecuteAsOwner", f"{S}\\AppDB", S, database="AppDB", databaseIsTrustworthy=True,
         ownerHasSysadmin=False, ownerHasControlServer=True, ownerLoginName="dbowner"),
    edge("MSSQL_ExecuteAsOwner", f"{S}\\OpsDB", S, database="OpsDB", databaseIsTrustworthy=True,
         ownerHasSysadmin=True, ownerHasControlServer=True, ownerLoginName="CORP\\alice"),
    edge("MSSQL_IsTrustedBy", f"{S}\\AppDB", S),
    edge("MSSQL_HostFor", f"{D}-1002", S),
    edge("MSSQL_ExecuteOnHost", S, f"{D}-1002"),
    edge("MSSQL_ServiceAccountFor", f"{D}-1201", S, general="This domain account runs the SQL Server service."),
    edge("MSSQL_GetAdminTGS", f"{D}-1201", S),
    edge("MSSQL_CoerceAndRelayToMSSQL", f"CORP.LOCAL-S-1-5-11", f"CORP\\alice@{S}"),
    edge("HasSession", f"{D}-1002", f"{D}-1201"),
    # The link from WS01 signs in to APP01 as linkadmin, measured as linkadmin.
    edge("MSSQL_LinkedAsAdmin", S, S2, remoteLogin="linkadmin", remoteCurrentLogin="linkadmin",
         usesImpersonation=False, path="ws01 -> app01", **linked),
    edge("MSSQL_LinkedTo", S, S2, remoteLogin="linkadmin", remoteCurrentLogin="linkadmin",
         usesImpersonation=False, **linked),
    # The link back was measured under another mapping (the collector's own).
    edge("MSSQL_LinkedAsAdmin", S2, S, remoteLogin="sa_link", remoteCurrentLogin="CORP\\scanner",
         usesImpersonation=False, path="app01 -> ws01", **linked),
    # APP01:1433
    edge("MSSQL_HasLogin", f"{D}-1102", f"CORP\\bob@{S2}"),
    edge("MSSQL_HasLogin", f"{D}-1104", f"CORP\\dave@{S2}"),
    edge("MSSQL_ExecuteAs", f"public@{S2}", f"svc_app@{S2}"),
    edge("MSSQL_Impersonate", f"public@{S2}", f"svc_app@{S2}", traversable=False),
    edge("MSSQL_MemberOf", f"svc_app@{S2}", f"sysadmin@{S2}"),
    edge("MSSQL_ControlServer", f"sysadmin@{S2}", S2),
    edge("MSSQL_ImpersonateAnyLogin", f"CORP\\dave@{S2}", S2, traversable=False),
    # Not something MSSQLHound writes: Pathwarden derives this kind itself,
    # so one in a file is context only.
    edge("MSSQL_RunsAs", S2, f"{D}-1201"),
    # APP01:1434
    edge("MSSQL_HasLogin", f"{D}-1103", f"CORP\\carol@{S3}"),
    edge("MSSQL_MemberOf", f"CORP\\carol@{S3}", f"sysadmin@{S3}"),
    edge("MSSQL_ControlServer", f"sysadmin@{S3}", S3),
    edge("MSSQL_ServiceAccountFor", f"{D}-1104", S3),
    edge("MSSQL_GetAdminTGS", f"{D}-1104", S3),
]
write(os.path.join(OUT, "mssqlhound_corp", "mssql-corp.json"),
      {"metadata": {"source_kind": "MSSQL_Base"}, "graph": {"nodes": nodes, "edges": edges}})


# ---------------------------------------------------------- ConfigManBearPig
def cmbp(dirname, site, server, root, admins, devices, extra_sccm=(), extra_ad=(), mssql=None, extra_nodes=()):
    """One ConfigManBearPig collection: sccm_*, ad_* (untagged) and mssql_* files."""
    sn = [node(site, "SCCM_Site", name=f"Site {site}", displayname=f"Site {site}", environmentid=root,
               collectionSource=[], siteCode=site, parentSiteCode="", rootSiteCode=root,
               siteType="Primary Site", siteServerName=server, siteServerFQDN=server,
               SQLServerName=server, SQLDatabaseName=f"CM_{site}", version="5.00.9106.1000")]
    sn.append(node(f"SMS00001@{site}", "SCCM_Collection", name="All Systems", collectionID="SMS00001",
                   rootSiteCode=root, sourceSiteCode=site, members=[d for d, _ in devices]))
    se = [edge("SCCM_Contains", site, f"SMS00001@{site}", collectionSource=["SCCM_Invoke-PostProcessing"],
               composed=False)]
    an = []
    ae = []
    for sid, name, role in admins:
        uid = f"CORP\\{name.upper()}@{site}"
        sn.append(node(uid, "SCCM_AdminUser", name=f"corp\\{name}", adminSid=sid, isGroup=False,
                       rootSiteCode=root, roles=[role]))
        se.append(edge("SCCM_Contains", site, uid, collectionSource=["SCCM_Invoke-PostProcessing"]))
        ae.append(edge("SCCM_IsMappedTo", sid, uid, collectionSource=["AdminService-SMS_Admin"], SCCMInfra=True))
        if role == "AllPermissions":
            se.append(edge("SCCM_AllPermissions", uid, site, collectionSource=["SCCM_Invoke-PostProcessing"]))
        else:
            for dev, _ in devices:
                se.append(edge(f"SCCM_{role}", uid, dev, collectionSource=["SCCM_Invoke-PostProcessing"]))
    for dev, host in devices:
        sn.append(node(dev, "SCCM_ClientDevice", name=dev, siteCode=site, ADDomainSID=D))
        se.append(edge("SCCM_HasClient", site, dev, collectionSource=["AdminService-ClientDevices"]))
        se.append(edge("SCCM_HasMember", f"SMS00001@{site}", dev, traversable=False,
                       collectionSource=["AdminService-SMS_FullCollectionMembership"]))
        ae.append(edge("SCCM_SameHostAs", dev, host, collectionSource=["SCCM_Invoke-PostProcessing"]))
    sn.extend(extra_nodes)
    se.extend(extra_sccm)
    ae.extend(extra_ad)
    d = os.path.join(OUT, dirname)
    write(os.path.join(d, "sccm_nodes-1.json"),
          {"metadata": {"source_kind": "SCCM"}, "graph": {"nodes": sn, "edges": []}}, metadata_last=True)
    write(os.path.join(d, "sccm_edges-1.json"),
          {"metadata": {"source_kind": "SCCM"}, "graph": {"nodes": [], "edges": se}}, metadata_last=True)
    write(os.path.join(d, "ad_edges-1.json"), {"graph": {"nodes": [], "edges": ae}})
    if mssql:
        mn, me = mssql
        write(os.path.join(d, "mssql_nodes-1.json"),
              {"metadata": {"source_kind": "MSSQL"}, "graph": {"nodes": mn, "edges": []}}, metadata_last=True)
        write(os.path.join(d, "mssql_edges-1.json"),
              {"metadata": {"source_kind": "MSSQL"}, "graph": {"nodes": [], "edges": me}}, metadata_last=True)


DB = f"{D}-1002:1433"  # the site database on WS01
assumed = dict(assumed=True, assumptionBasis="relay feasibility assumed from role topology + NTLM/SMB-signing state")
cmbp(
    "configmanbearpig", "PS1", "ps1-pss.corp.local", "PS1",
    admins=[(f"{D}-1101", "alice", "FullAdministrator"), (f"{D}-1102", "bob", "AllPermissions")],
    devices=[("GUID:0D0C0001-0000-0000-0000-000000000001", f"{D}-1000"),
             ("GUID:0A0B0001-0000-0000-0000-000000000002", f"{D}-1001")],
    extra_sccm=[
        edge("SCCM_AssignAllPermissions", f"{DB}\\CM_PS1", "PS1", collectionSource=["SCCM_Add-MSSQLServerNodesAndEdges"]),
        # Assumed: the SMS Provider role on APP01 was inferred.
        edge("SCCM_AssignAllPermissions", f"{D}-1001", "PS1",
             collectionSource=["Assumed-AssignAllPermissions", "SCCM_Invoke-PostProcessing"], **assumed),
        edge("SCCM_HasClient", "PS1", "GUID:0FFF0001-0000-0000-0000-000000000003",
             collectionSource=["Assumed-PossibleClientDevice", "LDAP-CmRcService"], **assumed),
    ],
    extra_ad=[
        edge("SCCM_CoerceAndRelayToSMB", "CORP.LOCAL-S-1-5-11", f"{D}-1000",
             collectionSource=["Assumed-CoerceRelay", "RemoteRegistry-SMBSigningCheck"], **assumed),
        edge("SCCM_CoerceAndRelayToAdminService", "CORP.LOCAL-S-1-5-11", "PS1",
             collectionSource=["Assumed-CoerceRelay", "Post-processing"], **assumed),
        edge("SCCM_LocalAdminRequired", f"{D}-1002", f"{D}-1000",
             collectionSource=["Assumed-LocalAdminRequired", "SCCM_Invoke-PostProcessing"], **assumed),
        edge("SCCM_SameHostAs", "GUID:0FFF0001-0000-0000-0000-000000000003", f"{D}-1000",
             collectionSource=["SCCM_Invoke-PostProcessing"], **assumed),
        edge("SCCM_HasPrimaryUser", "GUID:0A0B0001-0000-0000-0000-000000000002", f"{D}-1201",
             collectionSource=["AdminService-ClientDevices"]),
        edge("SCCM_HasADLastLogonUser", "GUID:0A0B0001-0000-0000-0000-000000000002", f"{D}-1201",
             collectionSource=["AdminService-ClientDevices"]),
        edge("MSSQL_HasLogin", f"{D}-1103", f"CORP\\CAROL@{DB}", collectionSource=["AdminService-SiteDefinition"]),
        edge("MemberOf", f"{D}-1104", f"{D}-512", collectionSource=["AdminService-SMS_R_User"]),
        edge("HasSession", f"{D}-1002", f"{D}-1201", collectionSource=["RemoteRegistry-CurrentUser"]),
    ],
    extra_nodes=[node("GUID:0FFF0001-0000-0000-0000-000000000003", "SCCM_ClientDevice",
                      name="DC01.CORP.LOCAL", siteCode="PS1", isPossibleClient=True,
                      collectionSource=["LDAP-CmRcService"])],
    mssql=(
        [node(DB, "MSSQL_Server", name="ws01.corp.local", SCCMInfra=True, SCCMSite="PS1", databases=["CM_PS1"]),
         node(f"CORP\\CAROL@{DB}", "MSSQL_Login", name="CORP\\CAROL", type="WINDOWS_LOGIN", disabled=False),
         node(f"sysadmin@{DB}", "MSSQL_ServerRole", name="sysadmin", isFixedRole=True),
         node(f"{DB}\\CM_PS1", "MSSQL_Database", name="CM_PS1", SCCMSite="PS1")],
        [edge("MSSQL_MemberOf", f"CORP\\CAROL@{DB}", f"sysadmin@{DB}"),
         edge("MSSQL_ControlServer", f"sysadmin@{DB}", DB),
         edge("MSSQL_Contains", DB, f"{DB}\\CM_PS1")],
    ),
)
# Another hierarchy whose primary site is also PS1 (another collection):
# DAVE administers its clients; WS01 is one of them.
cmbp(
    "configmanbearpig_other", "PS1", "ps1.other.corp.local", "PS1",
    admins=[(f"{D}-1104", "dave", "FullAdministrator")],
    devices=[("GUID:0E0E0001-0000-0000-0000-000000000004", f"{D}-1002")],
)
