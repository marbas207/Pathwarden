"""Generates a large synthetic Active Directory collection in SharpHound v6
format, for scale testing. Deterministic (seeded), so runs are comparable.

    python scripts/gen_scale_fixture.py --computers 500000 --users 750000 --out data/scale

The shape follows a typical large single-domain enterprise:

- 20 regions x 10 sites; each site has Users, Workstations and Servers OUs
- per site: an all-users group, a helpdesk group (local admin on the site's
  workstations, password reset on its users through an inherited ACE) and a
  server admins group (local admin on its servers); region helpdesk groups
  nest the site ones; department and application groups on top
- 3% servers; every workstation has its owner's session, servers have
  admin sessions; 90% of computers report sessions and local groups
- default ACEs on every object (Domain Admins owner, Domain Admins /
  Enterprise Admins / Account Operators full control), as SharpHound reports
- regions differ the way real ones do. Each region is well run, average or
  messy (about 40/40/20):
  - well run: admins use separate admin accounts that the helpdesk can't
    reset, no Domain Admin logons on member servers, no stray rights
  - average: admins use their daily accounts; in some sites the site's users
    are local admins on their own workstations; Domain Admins occasionally
    log on to a server
  - messy: all of that more often, plus a helpdesk that can edit the GPO
    linked to its region, stray GenericWrite rights over server admin
    groups, and weaker collection coverage
- domain-wide: Kerberoastable service accounts (one in Domain Admins),
  AS-REP roastable users, unconstrained delegation on a few servers, a DCSync
  service account, and a GPO Domain Users control (linked to one site)

Output goes to data/ (gitignored); it is synthetic but still large.

`--stage 1` to `--stage 4` write the same company one to four weeks before
`--stage 5` (the default, unchanged), for the demo's five weekly runs, so
every kind of change over time shows. None of it draws from the random
stream, so everything else is the same in all five:

- a fix: the first average region's helpdesk can edit its GPO in stage 1
  only
- a finding back after a fix: DA-ADMIN04 is logged on to the second and
  third servers of the second half of the average regions' sites in stage 1,
  not in 2, again in 3, and not from 4
- objects gained, then a fix: DA-ADMIN03 is logged on to the second and third
  servers of the first half's sites in stages 1 to 4, and to their fourth
  servers too in stages 3 and 4
- a completeness drop: the first well-run region's computers aren't
  collected in stage 3
- a member in and out of Tier Zero: a regular user is in Domain Admins in
  stage 4 only; a second Kerberoastable service account (SVC-00005) is in
  Domain Admins in stages 1 to 4
- new paths into a zone of the messy region's server admins: the last two
  stray rights over those groups appear in stages 4 and 5
- a new finding: the first Domain Admin logon on a collected member server
  (in the first half's sites) appears in stage 5
- big swings in who can take over Tier Zero: Domain Users is nested into the
  first average region's first server admin group in stage 1 only (nearly
  every account); a software rollout makes the second average region's users local
  admins on their workstations in stages 2 and 3, and the first's too in
  stage 3, until stage 4
"""
import argparse
import json
import random
import time
from pathlib import Path

DOMAIN = "SCALE.LOCAL"
DSID = "S-1-5-21-1111-2222-3333"
NOW = 1_791_000_000  # fixed "collection time" (2026-10)
DAY = 86_400


def sid(rid):
    return f"{DSID}-{rid}"


def builtin(rid):
    return f"{DOMAIN}-S-1-5-32-{rid}"


def ace(principal, ptype, right, inherited=False):
    return {"PrincipalSID": principal, "PrincipalType": ptype, "RightName": right, "IsInherited": inherited}


def ref(oid, otype):
    return {"ObjectIdentifier": oid, "ObjectType": otype}


DA, EA, DU, DC_GROUP, DCOMP = sid(512), sid(519), sid(513), sid(516), sid(515)
ACCOUNT_OPS = builtin(548)
# Every object carries these, as in a real directory: no attack path, but
# they are what ingest has to wade through.
DEFAULT_ACES = [
    ace(DA, "Group", "Owns"),
    ace(DA, "Group", "GenericAll"),
    ace(EA, "Group", "GenericAll", True),
    ace(builtin(544), "Group", "GenericAll", True),
]


class Writer:
    """Streams one collector file: {"data": [...], "meta": {...}}."""

    prefix = "20261001020000"

    def __init__(self, out, kind):
        self.path = out / f"{Writer.prefix}_{kind}.json"
        self.f = open(self.path, "w", encoding="utf-8", newline="\n")
        self.kind = kind
        self.count = 0
        self.f.write('{"data":[')

    def add(self, obj):
        if self.count:
            self.f.write(",\n")
        self.f.write(json.dumps(obj, separators=(",", ":")))
        self.count += 1

    def close(self):
        meta = {"methods": 0, "type": self.kind, "count": self.count, "version": 6}
        self.f.write('],"meta":' + json.dumps(meta) + "}\n")
        self.f.close()
        return self.path


def props(name, **extra):
    p = {"name": f"{name}@{DOMAIN}", "domain": DOMAIN, "domainsid": DSID}
    p.update(extra)
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--computers", type=int, default=500_000)
    ap.add_argument("--users", type=int, default=750_000)
    ap.add_argument("--regions", type=int, default=20)
    ap.add_argument("--sites", type=int, default=10, help="sites per region")
    ap.add_argument("--out", default="data/scale")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--stage", type=int, choices=(1, 2, 3, 4, 5), default=5,
                    help="the demo's five weekly runs: 1 to 4 are the same company four to one weeks earlier")
    a = ap.parse_args()
    global NOW
    stage = a.stage
    NOW -= (5 - stage) * 7 * DAY
    Writer.prefix = {1: "20260903020000", 2: "20260910020000", 3: "20260917020000", 4: "20260924020000", 5: "20261001020000"}[stage]
    rnd = random.Random(a.seed)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.json"):
        old.unlink()
    t0 = time.time()

    next_rid = [5000]

    def new_rid():
        next_rid[0] += 1
        return next_rid[0]

    # ------------------------------------------------------------ structure
    ou_guid = lambda n: f"0U000000-0000-0000-0000-{n:012d}"
    gpo_guid = lambda n: f"6P000000-0000-0000-0000-{n:012d}"
    n_sites = a.regions * a.sites
    regions = [f"R{r:02d}" for r in range(a.regions)]
    sites = [(r, f"R{r:02d}S{s:02d}") for r in range(a.regions) for s in range(a.sites)]
    # How well each region is run (fixed by the seed): the main source of
    # variety in exposure between regions and sites.
    n_messy = max(1, round(a.regions * 0.2))
    n_mature = max(1, round(a.regions * 0.4)) if a.regions > 2 else 0
    maturity = ["messy"] * n_messy + ["mature"] * n_mature
    maturity += ["average"] * (a.regions - len(maturity))
    rnd.shuffle(maturity)
    # AS-REP-roastable accounts ("Do not require Kerberos preauthentication"):
    # two users in the messy region (on paths to Tier Zero), one in an
    # average region, one in a well-run region and one service account
    # without an SPN. Named, not drawn, so the rest of the data is unchanged.
    def first(kind):
        return next((r for r in range(a.regions) if maturity[r] == kind), 0)
    asrep = {f"R{first('messy'):02d}S01-U00042", f"R{first('messy'):02d}S02-U00311",
             f"R{first('average'):02d}S00-U00120", f"R{first('mature'):02d}S03-U00007", "SVC-00003"}
    # Per region and site: chance a site's users are local admins on their own
    # workstations, chance a member server has a Domain Admin logged on,
    # chance a workstation has a helpdesk session, and collection coverage.
    profile = {
        "mature": {"users_admin": 0.0, "da_session": 0.0, "helpdesk_session": 0.0, "collected": 0.97},
        "average": {"users_admin": 0.25, "da_session": 0.02, "helpdesk_session": 0.002, "collected": 0.88},
        "messy": {"users_admin": 0.7, "da_session": 0.08, "helpdesk_session": 0.006, "collected": 0.7},
    }
    site_users_admin = {s: rnd.random() < profile[maturity[r]]["users_admin"] for r, s in sites}
    ou_id = {}
    k = 0
    for name in ["Domain Controllers", "Tier0", "Service Accounts"] + regions:
        ou_id[name] = ou_guid(k)
        k += 1
    for _, s in sites:
        for leaf in ("Users", "Workstations", "Servers"):
            ou_id[f"{s}/{leaf}"] = ou_guid(k)
            k += 1
        ou_id[s] = ou_guid(k)
        k += 1

    # Groups (rid -> name, members filled in later).
    groups = {}  # sid -> {"name":..., "members": [refs], "admincount": bool, "ou": guid}

    def group(name, ou, admin=False, rid=None):
        gsid = sid(rid) if rid else sid(new_rid())
        groups[gsid] = {"name": name, "members": [], "admincount": admin, "ou": ou}
        return gsid

    for rid, name in [(512, "DOMAIN ADMINS"), (519, "ENTERPRISE ADMINS"), (513, "DOMAIN USERS"),
                      (515, "DOMAIN COMPUTERS"), (516, "DOMAIN CONTROLLERS"), (518, "SCHEMA ADMINS")]:
        group(name, ou_id["Tier0"], admin=rid in (512, 519, 518), rid=rid)
    region_helpdesk = {r: group(f"{regions[r]}-HELPDESK", ou_id[regions[r]]) for r in range(a.regions)}
    site_users, site_helpdesk, site_srvadmins = {}, {}, {}
    for r, s in sites:
        site_users[s] = group(f"{s}-USERS", ou_id[s])
        site_helpdesk[s] = group(f"{s}-HELPDESK", ou_id[s])
        site_srvadmins[s] = group(f"{s}-SERVERADMINS", ou_id[s])
        groups[region_helpdesk[r]]["members"].append(ref(site_helpdesk[s], "Group"))
    departments = [group(f"DEPT-{i:03d}", ou_id[regions[i % a.regions]]) for i in range(500)]
    apps = [group(f"APP-{i:05d}", ou_id[regions[i % a.regions]]) for i in range(max(100, a.users // 40))]
    sql_admins = group("SQL-ADMINS", ou_id["Service Accounts"])

    # GPOs: default policies, one per region (edited by that region's helpdesk:
    # a classic "helpdesk owns every workstation in the region" path).
    gpos = {gpo_guid(0): ("DEFAULT DOMAIN POLICY", []), gpo_guid(1): ("DEFAULT DOMAIN CONTROLLERS POLICY", [])}
    region_gpo = {}
    # Stage 1: the first average region's helpdesk can edit its GPO too.
    early_gpo = next((r for r in range(a.regions) if maturity[r] == "average"), None) if stage == 1 else None
    for r in range(a.regions):
        g = gpo_guid(10 + r)
        region_gpo[r] = g
        edits = [ace(region_helpdesk[r], "Group", "GenericWrite")] if maturity[r] == "messy" or r == early_gpo else []
        gpos[g] = (f"{regions[r]}-WORKSTATION-BASELINE", edits)
    broad_gpo = gpo_guid(99)
    gpos[broad_gpo] = ("LEGACY-PRINTERS", [ace(DU, "Group", "GenericAll")])  # misconfiguration

    # ------------------------------------------------------------ users
    w_users = Writer(out, "users")
    tier0_users, server_admin_users, helpdesk_users, svc_accounts = [], [], [], []
    users_by_site = {s: [] for _, s in sites}
    srvadmins_by_site, helpdesk_by_site = {}, {}

    def groups_members_users(gsid):
        return [m["ObjectIdentifier"] for m in groups[gsid]["members"] if m["ObjectType"] == "User"]
    n_admins_da = 40
    n_svc = max(50, a.users // 500)

    def user(name, ou, site=None, **extra):
        rid = new_rid()
        usid = sid(rid)
        base = {"enabled": rnd.random() > 0.04, "pwdlastset": NOW - rnd.randint(1, 400) * DAY,
                "lastlogontimestamp": NOW - rnd.randint(0, 120) * DAY}
        if name in asrep:
            base["dontreqpreauth"] = True
        base.update(extra)
        p = props(name, **base)
        aces = list(DEFAULT_ACES)
        if site is not None:
            # Helpdesk resets passwords for everyone in its region (inherited
            # from the region OU), as many organisations delegate it.
            aces.append(ace(region_helpdesk[site[0]], "Group", "ForceChangePassword", True))
            aces.append(ace(ACCOUNT_OPS, "Group", "GenericAll", True))
        w_users.add({"ObjectIdentifier": usid, "PrimaryGroupSID": DU, "Properties": p, "Aces": aces,
                     "AllowedToDelegate": [], "SPNTargets": [], "HasSIDHistory": [], "IsDeleted": False,
                     "ContainedBy": ref(ou, "OU")})
        return usid

    for i in range(n_admins_da):
        u = user(f"DA-ADMIN{i:02d}", ou_id["Tier0"], admincount=True,
                 pwdlastset=NOW - rnd.randint(30, 900) * DAY, enabled=True)
        tier0_users.append(u)
        groups[DA]["members"].append(ref(u, "User"))
    svc_sync = user("SVC-ADSYNC", ou_id["Service Accounts"], enabled=True)
    for i in range(n_svc):
        spn = [f"MSSQLSvc/sql{i:04d}.{DOMAIN.lower()}:1433"] if i % 5 == 0 else []
        u = user(f"SVC-{i:05d}", ou_id["Service Accounts"], enabled=True, hasspn=bool(spn),
                 serviceprincipalnames=spn, pwdneverexpires=True, pwdlastset=NOW - rnd.randint(400, 3000) * DAY)
        svc_accounts.append((u, bool(spn)))
    # Some Kerberoastable service accounts sit in admin groups.
    for u, has_spn in svc_accounts[:200]:
        if has_spn:
            groups[sql_admins]["members"].append(ref(u, "User"))
    groups[DA]["members"].append(ref(svc_accounts[0][0], "User"))  # the classic one
    if stage < 5 and len(svc_accounts) > 5:
        groups[DA]["members"].append(ref(svc_accounts[5][0], "User"))  # a second, removed by stage 5

    total_regular = a.users - n_admins_da - 1 - n_svc
    per_site = total_regular // n_sites
    for r, s in sites:
        ou = ou_id[f"{s}/Users"]
        for j in range(per_site):
            extra = {}
            if rnd.random() < 0.00006:
                extra["dontreqpreauth"] = True
            u = user(f"{s}-U{j:05d}", ou, site=(r, s), **extra)
            users_by_site[s].append(u)
            groups[site_users[s]]["members"].append(ref(u, "User"))
            groups[departments[rnd.randrange(len(departments))]]["members"].append(ref(u, "User"))
            if rnd.random() < 0.8:
                groups[apps[rnd.randrange(len(apps))]]["members"].append(ref(u, "User"))
        # Site admins come from the site's own staff.
        for u in rnd.sample(users_by_site[s], min(12, len(users_by_site[s]))):
            groups[site_helpdesk[s]]["members"].append(ref(u, "User"))
            helpdesk_users.append(u)
        if maturity[r] == "mature":
            # Separate admin accounts, outside the users OU, so the helpdesk's
            # password-reset delegation doesn't cover them.
            admins = [user(f"ADM-{s}-{k}", ou_id[regions[r]], enabled=True) for k in range(8)]
        else:
            admins = rnd.sample(users_by_site[s], min(8, len(users_by_site[s])))
        for u in admins:
            groups[site_srvadmins[s]]["members"].append(ref(u, "User"))
            server_admin_users.append(u)
        srvadmins_by_site[s] = admins
        helpdesk_by_site[s] = groups_members_users(site_helpdesk[s])
    users_path = w_users.close()
    # Stage 1: Domain Users nested into the first average region's first
    # server admin group (a bulk change gone wrong), so nearly every account
    # has a path (a Domain Admin is logged on to that site's servers in
    # stages 1 to 4); undone by stage 2. Not the messy region's: its server
    # admin groups are the demo's zone, which would then hold every account.
    first_avg = next((r for r in range(a.regions) if maturity[r] == "average"), None)
    if stage == 1 and first_avg is not None:
        groups[site_srvadmins[f"R{first_avg:02d}S00"]]["members"].append(ref(DU, "Group"))
    if stage == 4:
        # Added to Domain Admins for a week, then taken out again.
        groups[DA]["members"].append(ref(users_by_site[sites[0][1]][10], "User"))
    print(f"users: {w_users.count:,} ({time.time() - t0:.0f}s)")

    # Stray rights: ordinary users with GenericWrite over a server admins
    # group (a delegation that went wrong), reported on the group.
    stray = {}
    messy_sites = [s for r, s in sites if maturity[r] == "messy"]
    n_stray = max(5, len(messy_sites) * 3)
    # The last stray right appears in stage 5, the one before it in stage 4.
    kept = n_stray - {1: 2, 2: 2, 3: 2, 4: 1, 5: 0}[stage]
    for i in range(n_stray):
        s = rnd.choice(messy_sites)
        u = rnd.choice(users_by_site[s])
        if i < kept:
            stray.setdefault(site_srvadmins[s], []).append(u)

    # ------------------------------------------------------------ computers
    w_comp = Writer(out, "computers")
    n_dcs = 10
    n_servers = int(a.computers * 0.03)
    n_ws = a.computers - n_dcs - n_servers
    dcs, servers = [], []
    dc_ids = []

    def computer(name, ou, is_dc=False, admins=(), sessions=(), collected=True, **extra):
        rid = new_rid()
        csid = sid(rid)
        server = extra.pop("server", is_dc)
        p = props(f"{name}.{DOMAIN}", enabled=True, isdc=is_dc, haslaps=not is_dc and rnd.random() > 0.05,
                  lastlogontimestamp=NOW - rnd.randint(0, 20) * DAY,
                  operatingsystem="Windows Server 2022 Standard" if server else "Windows 11 Enterprise",
                  **extra)
        p["name"] = f"{name}.{DOMAIN}"
        aces = list(DEFAULT_ACES) + [ace(ACCOUNT_OPS, "Group", "GenericAll", True)]
        local_admins = [ref(DA, "Group")] + [ref(x, "Group") for x in admins]
        obj = {
            "ObjectIdentifier": csid, "PrimaryGroupSID": DC_GROUP if is_dc else DCOMP, "Properties": p, "Aces": aces,
            "AllowedToDelegate": [], "AllowedToAct": [], "HasSIDHistory": [], "DumpSMSAPassword": [],
            "Sessions": {"Results": [{"UserSID": u, "ComputerSID": csid} for u in sessions] if collected else [],
                         "Collected": collected, "FailureReason": None},
            "PrivilegedSessions": {"Results": [], "Collected": collected, "FailureReason": None},
            "RegistrySessions": {"Results": [], "Collected": collected, "FailureReason": None},
            "LocalGroups": [] if is_dc or not collected else [{
                "ObjectIdentifier": f"{csid}-544", "Name": f"ADMINISTRATORS@{name}.{DOMAIN}",
                "Results": local_admins, "LocalNames": [], "Collected": True, "FailureReason": None}],
            "UserRights": [], "DCRegistryData": None, "Status": None, "IsDC": is_dc, "DomainSID": DSID,
            "IsDeleted": False, "ContainedBy": ref(ou, "OU"),
        }
        if is_dc:
            obj["DCRegistryData"] = {"CertificateMappingMethods": {"Value": 24, "Collected": True},
                                     "StrongCertificateBindingEnforcement": {"Value": 2, "Collected": True}}
        w_comp.add(obj)
        return csid

    for i in range(n_dcs):
        c = computer(f"DC{i:02d}", ou_id["Domain Controllers"], is_dc=True, unconstraineddelegation=True)
        dc_ids.append(c)
        groups[DC_GROUP]["members"].append(ref(c, "Computer"))
    servers_per_site = max(1, n_servers // n_sites)
    ws_per_site = max(1, n_ws // n_sites)
    # Domain Admin logons by stage (see the top of this file): site -> [(user,
    # server numbers)], and the region whose computers aren't collected.
    average_sites = [s for r, s in sites if maturity[r] == "average"]
    half = len(average_sites) // 2
    extra_logons = {}
    if stage in (1, 3):
        for s in average_sites[half:]:
            extra_logons.setdefault(s, []).append((tier0_users[4], (1, 2)))
    if stage < 5:
        for s in average_sites[:half]:
            extra_logons.setdefault(s, []).append((tier0_users[3], (1, 2, 3) if stage in (3, 4) else (1, 2)))
    average_r = [r for r in range(a.regions) if maturity[r] == "average"]
    mature = [r for r in range(a.regions) if maturity[r] == "mature"]
    not_collected = {s for r, s in sites if stage == 3 and mature and r == mature[0]}
    first_da_logon = [True]  # the first collected one is new in stage 5
    for r, s in sites:
        prof = profile[maturity[r]]
        for j in range(servers_per_site):
            sess = rnd.sample(srvadmins_by_site[s], min(3, len(srvadmins_by_site[s])))
            if rnd.random() < prof["da_session"]:
                da = rnd.choice(tier0_users)
                collected = rnd.random() < prof["collected"]
                if not (stage < 5 and collected and first_da_logon[0]):
                    sess.append(da)
                if collected:
                    first_da_logon[0] = False
            else:
                collected = rnd.random() < prof["collected"]
            for u, js in extra_logons.get(s, ()):
                if j in js:
                    sess.append(u)
            if s in not_collected:
                collected = False
            c = computer(f"{s}-SRV{j:04d}", ou_id[f"{s}/Servers"], admins=[site_srvadmins[s]] + ([sql_admins] if j % 50 == 0 else []),
                         sessions=sess, collected=collected, server=True,
                         unconstraineddelegation=maturity[r] != "mature" and rnd.random() < 0.003)
            servers.append(c)
        site_users_list = users_by_site[s]
        # A software rollout makes users local admins on their workstations:
        # the second average region's in stages 2 and 3, the first's too in
        # stage 3; taken back in stage 4.
        rollout = (stage in (2, 3) and r in average_r[1:2]) or (stage == 3 and r in average_r[:1])
        ws_admins = [site_helpdesk[s]] + ([site_users[s]] if site_users_admin[s] or rollout else [])
        for j in range(ws_per_site):
            owner = site_users_list[j % len(site_users_list)]
            sess = [owner]
            if helpdesk_by_site[s] and rnd.random() < prof["helpdesk_session"]:
                sess.append(rnd.choice(helpdesk_by_site[s]))
            computer(f"{s}-WS{j:05d}", ou_id[f"{s}/Workstations"], admins=ws_admins,
                     sessions=sess, collected=rnd.random() < prof["collected"] and s not in not_collected)
    comp_path = w_comp.close()
    print(f"computers: {w_comp.count:,} ({time.time() - t0:.0f}s)")

    # ------------------------------------------------------------ groups
    w_groups = Writer(out, "groups")
    for gsid, g in groups.items():
        aces = list(DEFAULT_ACES)
        if g["name"].endswith("-USERS"):
            site = g["name"][: -len("-USERS")]
            aces.append(ace(site_helpdesk[site], "Group", "AddMember"))
        aces += [ace(u, "User", "GenericWrite") for u in stray.get(gsid, [])]
        w_groups.add({"ObjectIdentifier": gsid, "Properties": props(g["name"], admincount=g["admincount"]),
                      "Members": g["members"], "Aces": aces, "IsDeleted": False,
                      "ContainedBy": ref(g["ou"], "OU")})
    groups_path = w_groups.close()
    print(f"groups: {w_groups.count:,} ({time.time() - t0:.0f}s)")

    # ------------------------------------------------------------ OUs, GPOs, domain
    w_ous = Writer(out, "ous")
    for name in ["Domain Controllers", "Tier0", "Service Accounts"] + regions:
        links = []
        if name == "Domain Controllers":
            links = [{"GUID": gpo_guid(1), "IsEnforced": False}]
        elif name in regions:
            r = regions.index(name)
            links = [{"GUID": region_gpo[r], "IsEnforced": False}]
        child = [ref(ou_id[s], "OU") for r, s in sites if name in regions and regions[r] == name]
        w_ous.add({"ObjectIdentifier": ou_id[name], "Properties": props(name.upper().replace(" ", ""), distinguishedname=f"OU={name},DC=SCALE,DC=LOCAL"),
                   "Links": links, "ChildObjects": child, "Aces": list(DEFAULT_ACES), "IsDeleted": False,
                   "ContainedBy": ref(DSID, "Domain")})
    calm = [s for r, s in sites if maturity[r] == "mature"] or [sites[0][1]]
    printers_site = calm[0]
    for r, s in sites:
        w_ous.add({"ObjectIdentifier": ou_id[s], "Properties": props(s, distinguishedname=f"OU={s},OU={regions[r]},DC=SCALE,DC=LOCAL"),
                   "Links": [], "ChildObjects": [ref(ou_id[f"{s}/{leaf}"], "OU") for leaf in ("Users", "Workstations", "Servers")],
                   "Aces": list(DEFAULT_ACES), "IsDeleted": False, "ContainedBy": ref(ou_id[regions[r]], "OU")})
        for leaf in ("Users", "Workstations", "Servers"):
            w_ous.add({"ObjectIdentifier": ou_id[f"{s}/{leaf}"],
                       "Properties": props(f"{s}-{leaf.upper()}", distinguishedname=f"OU={leaf},OU={s},OU={regions[r]},DC=SCALE,DC=LOCAL"),
                       "Links": [{"GUID": broad_gpo, "IsEnforced": False}] if (s == printers_site and leaf == "Workstations") else [],
                       "ChildObjects": [], "Aces": list(DEFAULT_ACES) + (
                           [ace(region_helpdesk[r], "Group", "ForceChangePassword")] if leaf == "Users" else []),
                       "IsDeleted": False, "ContainedBy": ref(ou_id[s], "OU")})
    w_ous.close()

    w_gpos = Writer(out, "gpos")
    for g, (name, extra) in gpos.items():
        w_gpos.add({"ObjectIdentifier": g, "Properties": props(name), "Aces": list(DEFAULT_ACES) + extra, "IsDeleted": False})
    w_gpos.close()


    w_dom = Writer(out, "domains")
    dom_aces = list(DEFAULT_ACES) + [
        ace(DC_GROUP, "Group", "GetChanges"), ace(DC_GROUP, "Group", "GetChangesAll"),
        ace(builtin(544), "Group", "GetChanges"), ace(builtin(544), "Group", "GetChangesAll"),
        ace(svc_sync, "User", "GetChanges"), ace(svc_sync, "User", "GetChangesAll"),  # DCSync service account
    ]
    w_dom.add({"ObjectIdentifier": DSID, "Properties": props(DOMAIN.split(".")[0], distinguishedname="DC=SCALE,DC=LOCAL", functionallevel="2016"),
               "Aces": dom_aces, "Links": [{"GUID": gpo_guid(0), "IsEnforced": False}],
               "ChildObjects": [ref(ou_id[n], "OU") for n in ["Domain Controllers", "Tier0", "Service Accounts"] + regions],
               "Trusts": [], "GPOChanges": None, "IsDeleted": False, "IsACLProtected": False, "ContainedBy": None})
    w_dom.close()
    # The domain object's name is the domain itself.
    dom_file = out / f"{Writer.prefix}_domains.json"
    dom_file.write_text(dom_file.read_text(encoding="utf-8").replace(f'"name":"SCALE@{DOMAIN}"', f'"name":"{DOMAIN}"'), encoding="utf-8")

    print("regions:", ", ".join(f"{regions[r]}={maturity[r]}" for r in range(a.regions)))
    total = sum(p.stat().st_size for p in out.glob("*.json"))
    print(f"done in {time.time() - t0:.0f}s: {total / 1e9:.2f} GB in {out}")


if __name__ == "__main__":
    main()
