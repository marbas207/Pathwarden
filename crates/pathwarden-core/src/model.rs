use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::kinds::{self, ExtKind};
use crate::sid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NodeKind {
    User,
    Computer,
    Group,
    Domain,
    Gpo,
    Ou,
    Container,
    CertTemplate,
    EnterpriseCa,
    RootCa,
    AiaCa,
    NtAuthStore,
    IssuancePolicy,
    Base,
    /// A kind from an OpenGraph file that Pathwarden has no meaning for.
    External(ExtKind),
}

impl NodeKind {
    pub const ALL: &'static [NodeKind] = &[
        NodeKind::User,
        NodeKind::Computer,
        NodeKind::Group,
        NodeKind::Domain,
        NodeKind::Gpo,
        NodeKind::Ou,
        NodeKind::Container,
        NodeKind::CertTemplate,
        NodeKind::EnterpriseCa,
        NodeKind::RootCa,
        NodeKind::AiaCa,
        NodeKind::NtAuthStore,
        NodeKind::IssuancePolicy,
        NodeKind::Base,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            NodeKind::User => "User",
            NodeKind::Computer => "Computer",
            NodeKind::Group => "Group",
            NodeKind::Domain => "Domain",
            NodeKind::Gpo => "GPO",
            NodeKind::Ou => "OU",
            NodeKind::Container => "Container",
            NodeKind::CertTemplate => "CertTemplate",
            NodeKind::EnterpriseCa => "EnterpriseCA",
            NodeKind::RootCa => "RootCA",
            NodeKind::AiaCa => "AIACA",
            NodeKind::NtAuthStore => "NTAuthStore",
            NodeKind::IssuancePolicy => "IssuancePolicy",
            NodeKind::Base => "Base",
            NodeKind::External(k) => kinds::name(k),
        }
    }

    /// The kind in words, for a sentence ("the group CERT USERS"); `None`
    /// for a kind without one (Base, OpenGraph kinds).
    pub fn noun(self) -> Option<&'static str> {
        Some(match self {
            NodeKind::User => "user",
            NodeKind::Computer => "computer",
            NodeKind::Group => "group",
            NodeKind::Domain => "domain",
            NodeKind::Gpo => "GPO",
            NodeKind::Ou => "OU",
            NodeKind::Container => "container",
            NodeKind::CertTemplate => "certificate template",
            NodeKind::EnterpriseCa => "certification authority",
            NodeKind::RootCa => "root certification authority",
            NodeKind::AiaCa => "AIA certification authority",
            NodeKind::NtAuthStore => "NTAuth store",
            NodeKind::IssuancePolicy => "issuance policy",
            NodeKind::Base | NodeKind::External(_) => return None,
        })
    }

    pub fn is_external(self) -> bool {
        matches!(self, NodeKind::External(_))
    }

    /// Parses the `ObjectType` / `PrincipalType` strings used inside collector output.
    pub fn from_object_type(s: &str) -> Self {
        Self::ALL
            .iter()
            .copied()
            .find(|k| k.as_str().eq_ignore_ascii_case(s))
            .unwrap_or(NodeKind::Base)
    }

    /// Parses the `meta.type` of a collector output file.
    pub fn from_meta_type(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "users" => NodeKind::User,
            "computers" => NodeKind::Computer,
            "groups" => NodeKind::Group,
            "domains" => NodeKind::Domain,
            "gpos" => NodeKind::Gpo,
            "ous" => NodeKind::Ou,
            "containers" => NodeKind::Container,
            "certtemplates" => NodeKind::CertTemplate,
            "enterprisecas" => NodeKind::EnterpriseCa,
            "rootcas" => NodeKind::RootCa,
            "aiacas" => NodeKind::AiaCa,
            "ntauthstores" => NodeKind::NtAuthStore,
            "issuancepolicies" => NodeKind::IssuancePolicy,
            _ => return None,
        })
    }
}

impl Serialize for NodeKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NodeKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        // Only external names this process already knows: reading a kind
        // never grows the table.
        Ok(match kinds::lookup(&s) {
            Some(k)
                if !NodeKind::ALL
                    .iter()
                    .any(|n| n.as_str().eq_ignore_ascii_case(&s)) =>
            {
                NodeKind::External(k)
            }
            _ => NodeKind::from_object_type(&s),
        })
    }
}

macro_rules! edge_kinds {
    ($( $variant:ident => $name:literal, $traversable:literal; )*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum EdgeKind {
            $($variant,)*
            /// A kind from an OpenGraph file. Whether it is traversable is
            /// decided per analysis by the mapping packs
            /// ([`crate::graph::AdGraph::traversable`]), never here.
            External(ExtKind),
        }

        impl EdgeKind {
            /// Every native kind (external kinds are not listed).
            pub const ALL: &'static [EdgeKind] = &[$(EdgeKind::$variant),*];

            /// The BloodHound edge name.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(EdgeKind::$variant => $name,)*
                    EdgeKind::External(k) => kinds::name(k),
                }
            }

            /// Whether an attacker controlling the source can use this edge to gain
            /// control of the target. Non-traversable edges are kept for findings.
            /// Always false for external kinds: only the analysis's kind table
            /// can make one traversable.
            pub fn is_traversable(self) -> bool {
                match self {
                    $(EdgeKind::$variant => $traversable,)*
                    EdgeKind::External(_) => false,
                }
            }
        }
    };
}

// Every edge points from the principal that holds the capability to the object it
// can act on, so "source controls target" holds for all traversable kinds.
edge_kinds! {
    MemberOf => "MemberOf", true;
    HasSession => "HasSession", true;
    AdminTo => "AdminTo", true;
    CanRdp => "CanRDP", true;
    ExecuteDcom => "ExecuteDCOM", true;
    CanPsRemote => "CanPSRemote", true;
    AllowedToDelegate => "AllowedToDelegate", true;
    AllowedToAct => "AllowedToAct", true;
    HasSidHistory => "HasSIDHistory", true;
    Contains => "Contains", true;
    GpLink => "GPLink", true;
    SameForestTrust => "SameForestTrust", true;
    CrossForestTrust => "CrossForestTrust", false;
    DcSync => "DCSync", true;
    CoerceToTgt => "CoerceToTGT", true;
    GenericAll => "GenericAll", true;
    GenericWrite => "GenericWrite", true;
    WriteOwner => "WriteOwner", true;
    WriteDacl => "WriteDacl", true;
    Owns => "Owns", true;
    AddMember => "AddMember", true;
    AddSelf => "AddSelf", true;
    ForceChangePassword => "ForceChangePassword", true;
    AllExtendedRights => "AllExtendedRights", true;
    AddKeyCredentialLink => "AddKeyCredentialLink", true;
    AddAllowedToAct => "AddAllowedToAct", true;
    ReadLapsPassword => "ReadLAPSPassword", true;
    ReadGmsaPassword => "ReadGMSAPassword", true;
    SyncLapsPassword => "SyncLAPSPassword", true;
    WriteSpn => "WriteSPN", true;
    WriteAccountRestrictions => "WriteAccountRestrictions", true;
    WriteGpLink => "WriteGPLink", true;
    GetChanges => "GetChanges", false;
    GetChangesAll => "GetChangesAll", false;
    GetChangesInFilteredSet => "GetChangesInFilteredSet", false;
    OwnsLimitedRights => "OwnsLimitedRights", false;
    WriteOwnerLimitedRights => "WriteOwnerLimitedRights", false;
    Enroll => "Enroll", false;
    // ManageCA lets a principal reconfigure the CA (e.g. enable
    // EDITF_ATTRIBUTESUBJECTALTNAME2 or approve its own requests): ESC7.
    ManageCa => "ManageCA", true;
    ManageCertificates => "ManageCertificates", false;
    WritePkiEnrollmentFlag => "WritePKIEnrollmentFlag", false;
    WritePkiNameFlag => "WritePKINameFlag", false;
    // AD CS structure (BloodHound CE names). Hosting a CA is control of it.
    PublishedTo => "PublishedTo", false;
    HostsCaService => "HostsCAService", true;
    RootCaFor => "RootCAFor", false;
    NtAuthStoreFor => "NTAuthStoreFor", false;
    TrustedForNtAuth => "TrustedForNTAuth", false;
    EnterpriseCaFor => "EnterpriseCAFor", false;
    IssuedSignedBy => "IssuedSignedBy", false;
    ExtendedByPolicy => "ExtendedByPolicy", false;
    OidGroupLink => "OIDGroupLink", false;
    DelegatedEnrollmentAgent => "DelegatedEnrollmentAgent", false;
    EnrollOnBehalfOf => "EnrollOnBehalfOf", false;
    // AD CS abuse, derived in post-processing.
    GoldenCert => "GoldenCert", true;
    AdcsEsc1 => "ADCSESC1", true;
    AdcsEsc3 => "ADCSESC3", true;
    AdcsEsc4 => "ADCSESC4", true;
    AdcsEsc6a => "ADCSESC6a", true;
    AdcsEsc6b => "ADCSESC6b", true;
    AdcsEsc9a => "ADCSESC9a", true;
    AdcsEsc9b => "ADCSESC9b", true;
    AdcsEsc10a => "ADCSESC10a", true;
    AdcsEsc10b => "ADCSESC10b", true;
    AdcsEsc13 => "ADCSESC13", true;
    // File permissions read from the domain controller's SYSVOL and NETLOGON
    // shares (Pathwarden's built-in collector, `crate::sysvol`). Kept after
    // the AD CS kinds: older explorer data indexes kinds by position.
    WriteGpoFiles => "WriteGPOFiles", true;
    WriteLogonScript => "WriteLogonScript", true;
    // A management system (SCCM, SCOM, ...) that runs code on a host it
    // manages, derived from directory data (see `mgmt`). Kept after the SYSVOL
    // kinds: explorer files written before it index kinds by position.
    ManagesHost => "ManagesHost", true;
    // A computer stores the password of a domain account a service runs as
    // (Pathwarden's built-in collector, `crate::storedcreds`). Kept after
    // ManagesHost: explorer files written before it index kinds by position.
    HasStoredCredential => "HasStoredCredential", true;
}

impl EdgeKind {
    /// Rights to log on to a computer remotely without being an administrator.
    pub fn is_remote_logon(self) -> bool {
        matches!(
            self,
            EdgeKind::CanRdp | EdgeKind::CanPsRemote | EdgeKind::ExecuteDcom
        )
    }

    /// AD CS abuse edges, each reported by its own ESC rule. GoldenCert is not
    /// included: it starts at a CA host, which is Tier Zero.
    pub fn is_adcs_abuse(self) -> bool {
        matches!(
            self,
            EdgeKind::AdcsEsc1
                | EdgeKind::AdcsEsc3
                | EdgeKind::AdcsEsc4
                | EdgeKind::AdcsEsc6a
                | EdgeKind::AdcsEsc6b
                | EdgeKind::AdcsEsc9a
                | EdgeKind::AdcsEsc9b
                | EdgeKind::AdcsEsc10a
                | EdgeKind::AdcsEsc10b
                | EdgeKind::AdcsEsc13
        )
    }

    /// A native kind by its BloodHound name (case-insensitive).
    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|k| k.as_str().eq_ignore_ascii_case(s))
    }

    /// [`from_name`](Self::from_name), or an external kind this process
    /// already knows. Never adds a name to the table.
    pub fn from_name_or_external(s: &str) -> Option<Self> {
        Self::from_name(s).or_else(|| kinds::lookup(s).map(EdgeKind::External))
    }

    pub fn is_external(self) -> bool {
        matches!(self, EdgeKind::External(_))
    }
}

impl Serialize for EdgeKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EdgeKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        EdgeKind::from_name_or_external(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown edge kind {s}")))
    }
}

/// Lenient accessors over a collector `Properties` map, tolerating the type
/// drift seen between collector versions (bools as 0/1, numbers as strings).
struct PropReader<'a>(&'a Map<String, Value>);

impl PropReader<'_> {
    fn s(&self, k: &str) -> Option<String> {
        self.0
            .get(k)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    }

    fn upper(&self, k: &str) -> Option<String> {
        self.s(k).map(|v| v.to_ascii_uppercase())
    }

    fn b(&self, k: &str) -> Option<bool> {
        match self.0.get(k)? {
            Value::Bool(b) => Some(*b),
            Value::Number(n) => n.as_i64().map(|v| v != 0),
            Value::String(v) => v.to_ascii_lowercase().parse().ok(),
            _ => None,
        }
    }

    fn i(&self, k: &str) -> Option<i64> {
        match self.0.get(k)? {
            Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
            Value::String(v) => v.parse().ok(),
            _ => None,
        }
    }

    /// A string array; `None` when the key is absent (unknown), as opposed to empty.
    fn list(&self, k: &str) -> Option<Vec<String>> {
        let a = self.0.get(k)?.as_array()?;
        Some(
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        )
    }
}

/// Why the built-in collector skipped a computer. A skipped computer
/// was never signed in to; it counts as not collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostSkip {
    /// Kerberos only, and the domain has no Kerberos name (SPN) for it.
    NoKerberosName,
    /// Signing required, and its SMB replies weren't (validly) signed.
    Unsigned,
    /// A reply answered another request than the one sent (a replayed or
    /// misdirected signed reply).
    BadReply,
    /// In another domain, behind a trust that allows only RC4.
    Rc4Trust,
}

/// A registry value read from a domain controller. Collectors without the
/// rights to read the registry report it as not collected, which is different
/// from a value that is not set (the Windows default applies).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DcSetting {
    #[default]
    Unknown,
    NotSet,
    Value(i64),
}

impl DcSetting {
    /// From a BloodHound `...raw` property: absent is unknown, negative is not set.
    pub fn from_raw(v: Option<i64>) -> Self {
        match v {
            None => DcSetting::Unknown,
            Some(v) if v < 0 => DcSetting::NotSet,
            Some(v) => DcSetting::Value(v),
        }
    }
}

/// userAccountControl flag of an interdomain trust account.
const UF_INTERDOMAIN_TRUST_ACCOUNT: i64 = 0x800;

/// userAccountControl flag of a computer account. A gMSA carries it too
/// (its class derives from computer), so on an object a collector reports
/// as a user it marks a managed service account.
pub const UF_WORKSTATION_TRUST_ACCOUNT: i64 = 0x1000;

/// The subset of collector properties the analysis uses. Everything else is
/// dropped at ingest to keep memory flat on large environments.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Props {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub domainsid: Option<String>,
    pub distinguishedname: Option<String>,
    pub description: Option<String>,
    pub operatingsystem: Option<String>,
    pub enabled: Option<bool>,
    pub hasspn: Option<bool>,
    pub dontreqpreauth: Option<bool>,
    pub admincount: Option<bool>,
    pub unconstraineddelegation: Option<bool>,
    pub trustedtoauth: Option<bool>,
    pub sensitive: Option<bool>,
    pub pwdneverexpires: Option<bool>,
    pub passwordnotreqd: Option<bool>,
    pub haslaps: Option<bool>,
    pub isdc: Option<bool>,
    pub pwdlastset: Option<i64>,
    pub lastlogontimestamp: Option<i64>,
    pub whencreated: Option<i64>,
    pub serviceprincipalnames: Vec<String>,
    /// Domain controllers: Schannel CertificateMappingMethods registry value.
    pub certificatemappingmethods: DcSetting,
    /// Domain controllers: Kdc StrongCertificateBindingEnforcement registry value.
    pub strongcertificatebindingenforcement: DcSetting,
    /// Domain controllers: the OS build from a Tier Zero settings file, which
    /// decides what the two values above mean when they are not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_build: Option<crate::dcsettings::DcOsBuild>,
    /// Computers: the collector retrieved logged-on sessions.
    pub sessions_collected: Option<bool>,
    /// Computers: the collector retrieved local group membership.
    pub local_groups_collected: Option<bool>,
    /// Computers: which of their session and local group lists the
    /// collector read ([`crate::opengraph::hosts::SESSION_LISTS`],
    /// [`crate::opengraph::hosts::GROUP_LISTS`]). Every list of a kind
    /// none of whose lists says whether it was read is set, as read.
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub host_lists: u8,
    /// Computers: which of those lists the collection didn't ask for
    /// (SharpHound's methods, or a list left uncollected with no reason or
    /// [`crate::ingest::NOT_CONTACTED`]): not targeted, not failed.
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub host_lists_unasked: u8,
    /// Computers: the collection asked for the computer's sessions (`None`:
    /// it doesn't say, read as asked). A Quick (DC only) collection asks
    /// for none. Worked out when the collection is read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions_targeted: Option<bool>,
    /// Computers: the collection asked for the computer's local groups, as
    /// [`Props::sessions_targeted`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_groups_targeted: Option<bool>,
    /// Computers: the built-in collector skipped the computer, and why
    /// (Kerberos only, required SMB signing). Read from its session
    /// lists' reasons ([`crate::ingest::SKIP_NO_KERBEROS_NAME`],
    /// [`crate::ingest::SKIP_UNSIGNED`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_skipped: Option<HostSkip>,
    /// Domains: the collector read the local groups GPOs set (SharpHound's
    /// GPOLocalGroup method). `None` when the collection doesn't say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpo_local_groups_collected: Option<bool>,
    /// Domains: the collector's `collected` flag. RustHound-CE also writes
    /// an object for each trusted domain, with `false` here: the domain is
    /// known through a trust, its data was not collected. `None` when the
    /// data doesn't say (SharpHound sets it to `true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected: Option<bool>,
    /// Users: the logon script (`scriptPath`), relative to NETLOGON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logonscript: Option<String>,
    /// Users: the userPrincipalName, upper case, kept only when it differs
    /// from the name (`SAM@DOMAIN`), for matching the accounts services
    /// run as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upn: Option<String>,
    /// Users: an interdomain trust account (userAccountControl 0x800), which
    /// RustHound-CE collects and SharpHound does not. Windows sets
    /// PASSWD_NOTREQD on these by design.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trustaccount: Option<bool>,
    /// A group or standalone managed service account (gMSA, sMSA). The domain
    /// gives it a 240-byte (120-character) random password and rotates it, so
    /// a ticket for its SPNs can't be cracked, and LAPS doesn't apply.
    /// SharpHound writes `gmsa` or `msa`; RustHound-CE and the built-in
    /// collector write neither, and ingest sets this instead: a gMSA is typed
    /// as a user keeping the computer-account bit (see
    /// [`UF_WORKSTATION_TRUST_ACCOUNT`]), an sMSA as a computer in the Managed
    /// Service Accounts container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managedpassword: Option<bool>,
    /// Domains: named by a trust's TargetDomainName though no record of the
    /// domain was collected. BloodHound CE writes that name onto the
    /// domain, so Cypher answers it ([`Self::name`] holds a record's name).
    /// Not serialized: a graph read back from disk loses it, so a future
    /// Cypher endpoint serving a saved graph would answer null for these
    /// domains. Cypher today runs only on freshly loaded collector data.
    #[serde(skip)]
    pub named_by_trust: bool,
    /// Every property the collector wrote, as it wrote it, for Cypher
    /// queries. Empty (no allocation) unless the load asked for it
    /// ([`crate::LoadOptions::all_properties`]). Never serialized: the keys
    /// are the graph's ([`crate::graph::AdGraph::prop_key`]), and the values
    /// can hold secrets (`userpassword`).
    #[serde(skip)]
    pub extra: PropBag,
}

/// A collector property value read from a [`PropBag`]: a JSON scalar, or a
/// list of them. Nulls and nested objects are not kept.
#[derive(Debug, Clone, PartialEq)]
pub enum PropValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<PropValue>),
}

/// Collector properties by interned key, packed into one byte buffer per
/// object: on a large domain `pathwarden query` pays this for every object,
/// so it is kept small. Each entry is the key (varint) and a tagged value:
/// booleans in the tag alone, integers as zigzag varints (a timestamp in 5
/// bytes, `-1` and `0` in 1), strings as a length and their bytes, lists as
/// a count and their values. A string many objects share (a domain, an
/// operating system) is stored once in the graph's [`PropStrings`] and
/// referenced by number. A lookup scans the entries, which is cheap for the
/// few dozen an object has.
#[derive(Debug, Clone, Default)]
pub struct PropBag(Box<[u8]>);

const TAG_FALSE: u8 = 0;
const TAG_TRUE: u8 = 1;
const TAG_INT: u8 = 2;
const TAG_FLOAT: u8 = 3;
const TAG_STR: u8 = 4;
const TAG_LIST: u8 = 5;
/// A string in [`PropStrings`], by number.
const TAG_SHARED: u8 = 6;

/// The property strings objects share, stored once per graph. A property
/// whose values turn out to be mostly distinct (names, GUIDs) stops being
/// shared after [`PropStrings::PER_KEY`] values, so the table stays small.
#[derive(Debug, Default)]
pub struct PropStrings {
    strings: Vec<Box<str>>,
    ids: std::collections::HashMap<Box<str>, u32>,
    /// Strings added for each property key.
    added: Vec<u32>,
}

impl PropStrings {
    /// Distinct values a property may add before its strings are stored
    /// inline instead.
    const PER_KEY: u32 = 1024;
    /// Longer strings are stored inline.
    const MAX_LEN: usize = 128;

    /// The number of `s` as a value of property `key`, added if the key
    /// still shares its values; `None` to store it inline.
    fn intern(&mut self, key: u16, s: &str) -> Option<u32> {
        if s.len() > Self::MAX_LEN || s.is_empty() {
            return None;
        }
        if let Some(&id) = self.ids.get(s) {
            return Some(id);
        }
        let key = usize::from(key);
        if self.added.len() <= key {
            self.added.resize(key + 1, 0);
        }
        if self.added[key] >= Self::PER_KEY {
            return None;
        }
        let id = u32::try_from(self.strings.len()).ok()?;
        self.added[key] += 1;
        self.strings.push(s.into());
        self.ids.insert(s.into(), id);
        Some(id)
    }

    fn get(&self, id: u32) -> &str {
        self.strings.get(id as usize).map_or("", |s| s)
    }
}

impl PropBag {
    /// Packs `entries`, skipping nulls and objects (inside lists too).
    pub fn encode<'a>(
        entries: impl IntoIterator<Item = (u16, &'a Value)>,
        strings: &mut PropStrings,
    ) -> Self {
        let mut buf = Vec::new();
        for (key, v) in entries {
            if keeps(v) {
                put_varint(&mut buf, u64::from(key));
                put_value(&mut buf, v, key, strings);
            }
        }
        PropBag(buf.into_boxed_slice())
    }

    pub fn get(&self, key: u16, strings: &PropStrings) -> Option<PropValue> {
        self.entries()
            .find(|(k, _)| *k == key)
            .map(|(_, mut at)| get_value(&self.0, &mut at, strings))
    }

    pub fn len(&self) -> usize {
        self.entries().count()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Heap bytes the bag holds (for measuring a load).
    pub fn heap_bytes(&self) -> usize {
        self.0.len()
    }

    /// Each entry's key, and where its value and the entry start.
    fn entries(&self) -> impl Iterator<Item = (u16, usize)> + '_ {
        let mut at = 0;
        std::iter::from_fn(move || {
            if at >= self.0.len() {
                return None;
            }
            let key = get_varint(&self.0, &mut at) as u16;
            let value = at;
            skip_value(&self.0, &mut at);
            Some((key, value))
        })
    }

    /// Merges a later record of the same object: its values win, as a later
    /// ingest's do in BloodHound CE, and keys only this bag has stay.
    fn overlay(&mut self, later: PropBag) {
        if later.is_empty() {
            return;
        }
        let have: Vec<u16> = later.entries().map(|(k, _)| k).collect();
        let mut buf = later.0.into_vec();
        let mut at = 0;
        while at < self.0.len() {
            let start = at;
            let key = get_varint(&self.0, &mut at) as u16;
            skip_value(&self.0, &mut at);
            if !have.contains(&key) {
                buf.extend_from_slice(&self.0[start..at]);
            }
        }
        self.0 = buf.into_boxed_slice();
    }
}

/// Whether a value is kept: nulls and objects are not.
fn is_zero_u8(n: &u8) -> bool {
    *n == 0
}

fn keeps(v: &Value) -> bool {
    !matches!(v, Value::Null | Value::Object(_))
}

fn put_varint(buf: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        buf.push(n as u8 | 0x80);
        n >>= 7;
    }
    buf.push(n as u8);
}

fn get_varint(buf: &[u8], at: &mut usize) -> u64 {
    let mut n = 0u64;
    let mut shift = 0;
    loop {
        let b = buf[*at];
        *at += 1;
        n |= u64::from(b & 0x7f) << shift;
        if b < 0x80 {
            return n;
        }
        shift += 7;
    }
}

fn put_value(buf: &mut Vec<u8>, v: &Value, key: u16, strings: &mut PropStrings) {
    match v {
        Value::Bool(b) => buf.push(if *b { TAG_TRUE } else { TAG_FALSE }),
        Value::Number(n) => match n.as_i64() {
            Some(i) => {
                buf.push(TAG_INT);
                put_varint(buf, ((i << 1) ^ (i >> 63)) as u64);
            }
            None => {
                buf.push(TAG_FLOAT);
                buf.extend_from_slice(&n.as_f64().unwrap_or(f64::NAN).to_le_bytes());
            }
        },
        Value::String(s) => match strings.intern(key, s) {
            Some(id) => {
                buf.push(TAG_SHARED);
                put_varint(buf, u64::from(id));
            }
            None => {
                buf.push(TAG_STR);
                put_varint(buf, s.len() as u64);
                buf.extend_from_slice(s.as_bytes());
            }
        },
        Value::Array(a) => {
            buf.push(TAG_LIST);
            put_varint(buf, a.iter().filter(|v| keeps(v)).count() as u64);
            for v in a.iter().filter(|v| keeps(v)) {
                put_value(buf, v, key, strings);
            }
        }
        Value::Null | Value::Object(_) => unreachable!("not kept"),
    }
}

fn get_value(buf: &[u8], at: &mut usize, strings: &PropStrings) -> PropValue {
    let tag = buf[*at];
    *at += 1;
    match tag {
        TAG_FALSE => PropValue::Bool(false),
        TAG_TRUE => PropValue::Bool(true),
        TAG_INT => {
            let z = get_varint(buf, at);
            PropValue::Int((z >> 1) as i64 ^ -((z & 1) as i64))
        }
        TAG_FLOAT => {
            let bytes: [u8; 8] = buf[*at..*at + 8].try_into().expect("8 bytes");
            *at += 8;
            PropValue::Float(f64::from_le_bytes(bytes))
        }
        TAG_STR => {
            let len = get_varint(buf, at) as usize;
            let s = String::from_utf8_lossy(&buf[*at..*at + len]).into_owned();
            *at += len;
            PropValue::Str(s)
        }
        TAG_SHARED => PropValue::Str(strings.get(get_varint(buf, at) as u32).to_string()),
        _ => {
            let n = get_varint(buf, at) as usize;
            PropValue::List((0..n).map(|_| get_value(buf, at, strings)).collect())
        }
    }
}

fn skip_value(buf: &[u8], at: &mut usize) {
    let tag = buf[*at];
    *at += 1;
    match tag {
        TAG_INT => {
            get_varint(buf, at);
        }
        TAG_FLOAT => *at += 8,
        TAG_STR => *at += get_varint(buf, at) as usize,
        TAG_SHARED => {
            get_varint(buf, at);
        }
        TAG_LIST => {
            for _ in 0..get_varint(buf, at) {
                skip_value(buf, at);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod prop_bag_tests {
    use super::*;

    #[test]
    fn values_read_back_as_written() {
        let m = serde_json::json!({
            "a": true, "b": false, "c": -1, "d": 0, "e": 1791753032,
            "f": i64::MIN, "g": 2.5, "h": "", "i": "héllo", "j": [],
            "k": ["x", null, {"o": 1}, 3], "l": null, "m": {"n": 1},
            "o": u64::MAX,
        });
        let m = m.as_object().unwrap();
        let mut strings = PropStrings::default();
        let bag = PropBag::encode(
            m.values().enumerate().map(|(i, v)| (i as u16, v)),
            &mut strings,
        );
        let get = |k: &str| bag.get(m.keys().position(|x| x == k).unwrap() as u16, &strings);
        assert_eq!(get("a"), Some(PropValue::Bool(true)));
        assert_eq!(get("b"), Some(PropValue::Bool(false)));
        assert_eq!(get("c"), Some(PropValue::Int(-1)));
        assert_eq!(get("d"), Some(PropValue::Int(0)));
        assert_eq!(get("e"), Some(PropValue::Int(1791753032)));
        assert_eq!(get("f"), Some(PropValue::Int(i64::MIN)));
        assert_eq!(get("g"), Some(PropValue::Float(2.5)));
        assert_eq!(get("h"), Some(PropValue::Str(String::new())));
        assert_eq!(get("i"), Some(PropValue::Str("héllo".into())));
        assert_eq!(get("j"), Some(PropValue::List(vec![])));
        assert_eq!(
            get("k"),
            Some(PropValue::List(vec![
                PropValue::Str("x".into()),
                PropValue::Int(3)
            ]))
        );
        assert_eq!(get("l"), None);
        assert_eq!(get("m"), None);
        assert_eq!(get("o"), Some(PropValue::Float(u64::MAX as f64)));
        assert_eq!(bag.len(), 12);
        // -1: the key, the tag and one byte of value.
        let small = PropBag::encode([(0, &serde_json::json!(-1))], &mut strings);
        assert_eq!(small.heap_bytes(), 3);
    }

    #[test]
    fn shared_strings_are_stored_once_until_a_key_turns_out_distinct() {
        let mut strings = PropStrings::default();
        let domain = serde_json::json!("CONTOSO.LOCAL");
        let a = PropBag::encode([(0, &domain)], &mut strings);
        let b = PropBag::encode([(0, &domain)], &mut strings);
        // The key, the tag and the string's number.
        assert_eq!((a.heap_bytes(), b.heap_bytes()), (3, 3));
        assert_eq!(
            b.get(0, &strings),
            Some(PropValue::Str("CONTOSO.LOCAL".into()))
        );
        // A key with many distinct values stops adding to the table.
        for i in 0..PropStrings::PER_KEY + 10 {
            let v = serde_json::json!(format!("guid-{i}"));
            let bag = PropBag::encode([(1, &v)], &mut strings);
            assert_eq!(
                bag.get(1, &strings),
                Some(PropValue::Str(format!("guid-{i}")))
            );
        }
        assert_eq!(strings.strings.len(), 1 + PropStrings::PER_KEY as usize);
    }

    #[test]
    fn a_later_record_wins() {
        let mut strings = PropStrings::default();
        let (one, two, three) = (
            serde_json::json!("first"),
            serde_json::json!("second"),
            serde_json::json!(7),
        );
        let mut bag = PropBag::encode([(1, &one), (2, &three)], &mut strings);
        bag.overlay(PropBag::encode([(1, &two)], &mut strings));
        assert_eq!(bag.get(1, &strings), Some(PropValue::Str("second".into())));
        assert_eq!(bag.get(2, &strings), Some(PropValue::Int(7)));
        assert_eq!(bag.len(), 2);
    }
}

impl Props {
    pub fn from_map(m: &Map<String, Value>) -> Self {
        let r = PropReader(m);
        Props {
            name: r.upper("name"),
            domain: r.upper("domain"),
            domainsid: r.upper("domainsid"),
            distinguishedname: r.upper("distinguishedname"),
            description: r.s("description"),
            operatingsystem: r.s("operatingsystem"),
            enabled: r.b("enabled"),
            hasspn: r.b("hasspn"),
            dontreqpreauth: r.b("dontreqpreauth"),
            admincount: r.b("admincount"),
            unconstraineddelegation: r.b("unconstraineddelegation"),
            trustedtoauth: r.b("trustedtoauth"),
            sensitive: r.b("sensitive"),
            pwdneverexpires: r.b("pwdneverexpires"),
            passwordnotreqd: r.b("passwordnotreqd"),
            haslaps: r.b("haslaps"),
            isdc: r.b("isdc"),
            pwdlastset: r.i("pwdlastset"),
            lastlogontimestamp: r.i("lastlogontimestamp"),
            whencreated: r.i("whencreated"),
            serviceprincipalnames: r.list("serviceprincipalnames").unwrap_or_default(),
            certificatemappingmethods: DcSetting::from_raw(r.i("certificatemappingmethodsraw")),
            strongcertificatebindingenforcement: DcSetting::from_raw(
                r.i("strongcertificatebindingenforcementraw"),
            ),
            os_build: None,
            sessions_collected: None,
            local_groups_collected: None,
            host_lists: 0,
            host_lists_unasked: 0,
            sessions_targeted: None,
            local_groups_targeted: None,
            host_skipped: None,
            gpo_local_groups_collected: None,
            collected: None,
            logonscript: r.s("logonscript"),
            upn: r
                .upper("userprincipalname")
                .filter(|u| Some(u) != r.upper("name").as_ref()),
            trustaccount: r
                .i("useraccountcontrol")
                .map(|uac| uac & UF_INTERDOMAIN_TRUST_ACCOUNT != 0),
            managedpassword: match (r.b("gmsa"), r.b("msa")) {
                (None, None) => None,
                (g, m) => Some(g == Some(true) || m == Some(true)),
            },
            named_by_trust: false,
            extra: PropBag::default(),
        }
    }

    /// Takes from `other` (another record of the same object) every value
    /// this one lacks. Values already set are kept: a partial record, such
    /// as the stub one domain's collection writes for another domain's
    /// built-in group, never clears what a fuller record set.
    pub fn fill_missing(&mut self, other: Props) {
        macro_rules! fill {
            ($($f:ident),*) => {
                $(if self.$f.is_none() {
                    self.$f = other.$f;
                })*
            };
        }
        fill!(
            name,
            domain,
            domainsid,
            distinguishedname,
            description,
            operatingsystem,
            enabled,
            hasspn,
            dontreqpreauth,
            admincount,
            unconstraineddelegation,
            trustedtoauth,
            sensitive,
            pwdneverexpires,
            passwordnotreqd,
            haslaps,
            isdc,
            pwdlastset,
            lastlogontimestamp,
            whencreated,
            logonscript,
            upn,
            trustaccount,
            managedpassword,
            os_build
        );
        if self.serviceprincipalnames.is_empty() {
            self.serviceprincipalnames = other.serviceprincipalnames;
        }
        self.extra.overlay(other.extra);
        if self.certificatemappingmethods == DcSetting::Unknown {
            self.certificatemappingmethods = other.certificatemappingmethods;
        }
        if self.strongcertificatebindingenforcement == DcSetting::Unknown {
            self.strongcertificatebindingenforcement = other.strongcertificatebindingenforcement;
        }
        self.host_skipped = self.host_skipped.or(other.host_skipped);
        // Read if any record read it; not asked only if no record that says
        // anything asked for it.
        let says = |lists: u8, unasked: u8| lists | unasked != 0;
        self.host_lists_unasked = match (
            says(self.host_lists, self.host_lists_unasked),
            says(other.host_lists, other.host_lists_unasked),
        ) {
            (true, true) => self.host_lists_unasked & other.host_lists_unasked,
            (false, _) => other.host_lists_unasked,
            (true, false) => self.host_lists_unasked,
        };
        self.host_lists |= other.host_lists;
        self.host_lists_unasked &= !self.host_lists;
        // Collected (or targeted) if any record says so.
        for (mine, theirs) in [
            (&mut self.sessions_collected, other.sessions_collected),
            (
                &mut self.local_groups_collected,
                other.local_groups_collected,
            ),
            (
                &mut self.gpo_local_groups_collected,
                other.gpo_local_groups_collected,
            ),
            (&mut self.sessions_targeted, other.sessions_targeted),
            (&mut self.local_groups_targeted, other.local_groups_targeted),
            (&mut self.collected, other.collected),
        ] {
            *mine = match (*mine, theirs) {
                (Some(a), Some(b)) => Some(a || b),
                (a, b) => a.or(b),
            };
        }
    }
}

pub const EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
pub const EKU_PKINIT_CLIENT: &str = "1.3.6.1.5.2.3.4";
pub const EKU_SMARTCARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";
pub const EKU_ANY_PURPOSE: &str = "2.5.29.37.0";
pub const EKU_CERT_REQUEST_AGENT: &str = "1.3.6.1.4.1.311.20.2.1";

/// AD CS properties for certificate templates, CAs, NTAuth stores and issuance
/// policies. `None` means the collector did not report the value: unknown, not
/// false. Boxed on [`Node`] so other objects pay one pointer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdcsProps {
    // Certificate templates.
    pub schemaversion: Option<i64>,
    pub authorizedsignatures: Option<i64>,
    pub enrolleesuppliessubject: Option<bool>,
    pub requiresmanagerapproval: Option<bool>,
    pub nosecurityextension: Option<bool>,
    pub authenticationenabled: Option<bool>,
    pub schannelauthenticationenabled: Option<bool>,
    pub subjectaltrequireupn: Option<bool>,
    pub subjectaltrequirespn: Option<bool>,
    pub subjectaltrequiredns: Option<bool>,
    pub subjectaltrequiredomaindns: Option<bool>,
    pub effectiveekus: Vec<String>,
    pub applicationpolicies: Vec<String>,
    pub certificatepolicy: Vec<String>,
    /// The collector reported the template's certificate (issuance) policies.
    /// RustHound-CE does not, so ESC13 cannot be checked from its data.
    #[serde(default)]
    pub certificatepolicycollected: bool,
    // Enterprise / root / AIA CAs and NTAuth stores.
    pub caname: Option<String>,
    pub dnshostname: Option<String>,
    pub certthumbprint: Option<String>,
    pub certchain: Vec<String>,
    pub certthumbprints: Vec<String>,
    /// EDITF_ATTRIBUTESUBJECTALTNAME2, only when actually read from the registry.
    pub isuserspecifiessanenabled: Option<bool>,
    /// IF_ENFORCEENCRYPTICERTREQUEST: the CA's RPC interface refuses requests
    /// without packet privacy (ESC11 when false). Only when read from the
    /// registry (Pathwarden's built-in Full collection).
    pub enforceencryptionforrequests: Option<bool>,
    /// Enrollment agent restrictions are configured (and were collected).
    pub enrollmentagentrestricted: bool,
    /// Web enrollment URLs that accept NTLM over HTTP, or HTTPS without EPA.
    pub vulnerableendpoints: Vec<String>,
    /// The collector said the CA publishes templates without saying which
    /// (RustHound-CE up to 2.5.23); every template of the forest is then
    /// treated as published to it.
    #[serde(default)]
    pub publishedtemplatesunresolved: bool,
    // Issuance policies.
    pub certtemplateoid: Option<String>,
}

impl AdcsProps {
    pub fn from_map(m: &Map<String, Value>) -> Self {
        let r = PropReader(m);
        let schema = r.i("schemaversion");
        let ekus = r.list("ekus");
        let app_policy = r.list("certificateapplicationpolicy");
        // SharpHound's definition: schema 1 templates use pKIExtendedKeyUsage,
        // later ones the application policy.
        let effective = r.list("effectiveekus").or_else(|| match (&ekus, schema) {
            (Some(e), Some(1)) if !e.is_empty() => ekus.clone(),
            _ => app_policy.clone(),
        });
        let has_eku_data = effective.is_some();
        let effective = effective.unwrap_or_default();
        let any = |oids: &[&str]| {
            effective.is_empty() || effective.iter().any(|e| oids.contains(&e.as_str()))
        };
        // An empty EKU list means "any purpose", which includes authentication.
        // RustHound-CE reports that as false, so it is recomputed here.
        let computed_auth = has_eku_data.then(|| {
            any(&[
                EKU_CLIENT_AUTH,
                EKU_PKINIT_CLIENT,
                EKU_SMARTCARD_LOGON,
                EKU_ANY_PURPOSE,
            ])
        });
        let computed_schannel = has_eku_data.then(|| any(&[EKU_CLIENT_AUTH, EKU_ANY_PURPOSE]));
        let upper_list = |k: &str| {
            r.list(k)
                .unwrap_or_default()
                .into_iter()
                .map(|v| v.to_ascii_uppercase())
                .collect::<Vec<_>>()
        };
        AdcsProps {
            schemaversion: schema,
            authorizedsignatures: r.i("authorizedsignatures"),
            enrolleesuppliessubject: r.b("enrolleesuppliessubject"),
            requiresmanagerapproval: r.b("requiresmanagerapproval"),
            nosecurityextension: r.b("nosecurityextension"),
            authenticationenabled: match (r.b("authenticationenabled"), computed_auth) {
                (Some(reported), Some(computed)) => Some(reported || computed),
                (reported, computed) => reported.or(computed),
            },
            schannelauthenticationenabled: r
                .b("schannelauthenticationenabled")
                .or(computed_schannel),
            subjectaltrequireupn: r.b("subjectaltrequireupn"),
            subjectaltrequirespn: r.b("subjectaltrequirespn"),
            subjectaltrequiredns: r.b("subjectaltrequiredns"),
            subjectaltrequiredomaindns: r.b("subjectaltrequiredomaindns"),
            effectiveekus: effective,
            applicationpolicies: r.list("applicationpolicies").unwrap_or_default(),
            certificatepolicy: r.list("certificatepolicy").unwrap_or_default(),
            certificatepolicycollected: r.list("certificatepolicy").is_some(),
            caname: r.s("caname"),
            dnshostname: r.s("dnshostname"),
            certthumbprint: r.upper("certthumbprint"),
            certchain: upper_list("certchain"),
            certthumbprints: upper_list("certthumbprints"),
            isuserspecifiessanenabled: None,
            enforceencryptionforrequests: None,
            enrollmentagentrestricted: false,
            vulnerableendpoints: Vec::new(),
            publishedtemplatesunresolved: false,
            certtemplateoid: r.s("certtemplateoid").or_else(|| r.s("oid")),
        }
    }

    /// Issuance does not need extra authorized signatures.
    pub fn no_extra_signatures(&self) -> bool {
        matches!(
            (self.schemaversion, self.authorizedsignatures),
            (Some(1), _) | (Some(_), Some(0))
        )
    }

    pub fn requires_dns_san(&self) -> bool {
        self.subjectaltrequiredns == Some(true) || self.subjectaltrequiredomaindns == Some(true)
    }

    pub fn has_eku(&self, oid: &str) -> bool {
        self.effectiveekus.iter().any(|e| e == oid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// Upper-cased ObjectIdentifier (SID or GUID).
    pub id: String,
    pub kind: NodeKind,
    pub name: String,
    pub domain: Option<String>,
    pub domain_sid: Option<String>,
    pub is_dc: bool,
    /// Referenced by another object but never present in the collected data.
    pub placeholder: bool,
    pub tier_zero: bool,
    pub tier_zero_reason: Option<String>,
    pub props: Props,
    pub adcs: Option<Box<AdcsProps>>,
    /// What OpenGraph files said about this object (sources, extra kinds,
    /// a few kept properties). `None` for objects only AD data mentions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Box<ExtNode>>,
}

/// Source index into [`crate::graph::AdGraph::og_sources`].
pub type SourceId = u16;

/// OpenGraph data attached to a node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtNode {
    /// Sources that mentioned the object.
    pub sources: Vec<SourceId>,
    /// External kinds the files gave it besides its own kind.
    pub kinds: Vec<ExtKind>,
    /// Properties kept from the files (an allow-list, capped in size;
    /// never secrets).
    pub props: Vec<(String, serde_json::Value)>,
    /// Created by an OpenGraph file: no AD data has it. Such objects never
    /// become Tier Zero by kind or SID, only by configuration.
    pub og_created: bool,
    /// AzureHound: the record gave the object a name (without one,
    /// [`Node::name`] holds its ID for display, and Cypher answers null).
    /// OpenGraph keeps the name its file wrote in [`Self::props`] instead.
    /// Not serialized: a graph read back from disk loses it, so a future
    /// Cypher endpoint serving a saved graph would answer null for every
    /// AzureHound name. Cypher today runs only on freshly loaded data.
    #[serde(skip)]
    pub named: bool,
}

impl ExtNode {
    pub fn prop(&self, key: &str) -> Option<&serde_json::Value> {
        self.props.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

impl Serialize for ExtKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(kinds::name(*self))
    }
}

impl<'de> Deserialize<'de> for ExtKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(kinds::lookup(&s).unwrap_or(kinds::OTHER))
    }
}

impl Node {
    pub fn placeholder(id: String, kind: NodeKind) -> Self {
        Node {
            name: sid::display_name(&id),
            domain: sid::split_prefixed(&id).0.map(str::to_owned),
            domain_sid: sid::domain_sid_of(&id),
            id,
            kind,
            is_dc: false,
            placeholder: true,
            tier_zero: false,
            tier_zero_reason: None,
            props: Props::default(),
            adcs: None,
            ext: None,
        }
    }

    /// Created from an OpenGraph file only (no AD data has the object).
    pub fn og_created(&self) -> bool {
        self.ext.as_ref().is_some_and(|e| e.og_created)
    }

    /// The AdminSDHolder container, whose permissions SDProp copies onto every
    /// protected (adminCount=1) account and group.
    pub fn is_adminsdholder(&self) -> bool {
        self.kind == NodeKind::Container
            && self
                .props
                .distinguishedname
                .as_deref()
                .is_some_and(|dn| dn.starts_with("CN=ADMINSDHOLDER,CN=SYSTEM,"))
    }

    pub fn is_enabled(&self) -> bool {
        self.props.enabled != Some(false)
    }
}
