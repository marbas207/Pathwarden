//! Serde shapes for BloodHound collector output (SharpHound v2+/RustHound-CE,
//! data format v5/v6). Every field is optional and nulls are tolerated, because
//! collectors disagree on what they emit.

use std::fmt;
use std::marker::PhantomData;

use serde::de::value::SeqAccessDeserializer;
use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use super::budget::{capped_vec, known_properties, opt_value, value, value_vec, BValue, Capped};

fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Debug, Deserialize)]
pub struct RawMeta {
    #[serde(rename = "type", default, deserialize_with = "nullable")]
    pub kind: String,
    #[serde(default)]
    pub version: Option<u32>,
    /// SharpHound's collection methods (a bit mask); RustHound-CE writes 0.
    #[serde(default, deserialize_with = "nullable")]
    pub methods: u64,
}

/// A list that collectors emit either as a bare array or as
/// `{"Results": [...], "Collected": bool, "FailureReason": ...}`.
#[derive(Debug)]
pub struct ResultSet<T> {
    pub items: Vec<T>,
    /// Whether the collector reached the host; `None` for the bare-array form.
    pub collected: Option<bool>,
    /// Why it did not, when the collector said (`FailureReason`).
    pub failure_reason: Option<String>,
}

impl<T> Default for ResultSet<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            collected: None,
            failure_reason: None,
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for ResultSet<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(ResultSetVisitor(PhantomData))
    }
}

/// Reads either form of [`ResultSet`] straight from the input (not through
/// a `Value`), with its list under the object's budget. Anything else
/// (`null`, a number, ...) is an empty set, as before.
struct ResultSetVisitor<T>(PhantomData<T>);

impl<'de, T: Deserialize<'de>> Visitor<'de> for ResultSetVisitor<T> {
    type Value = ResultSet<T>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a list, or an object with Results")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        let items = Capped::<T>::deserialize(SeqAccessDeserializer::new(seq))?.0;
        Ok(ResultSet {
            items,
            ..ResultSet::default()
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut set = ResultSet::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "Results" => set.items = map.next_value::<Capped<T>>()?.0,
                "Collected" => set.collected = map.next_value::<BValue>()?.0.as_bool(),
                "FailureReason" => {
                    set.failure_reason = map.next_value::<BValue>()?.0.as_str().map(str::to_string)
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(set)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(ResultSet::default())
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(ResultSet::default())
    }
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(ResultSet::default())
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(ResultSet::default())
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(ResultSet::default())
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(ResultSet::default())
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(ResultSet::default())
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TypedRef {
    #[serde(default, deserialize_with = "nullable")]
    pub object_identifier: String,
    #[serde(default, deserialize_with = "nullable")]
    pub object_type: String,
}

#[derive(Debug, Deserialize)]
pub struct RawAce {
    #[serde(rename = "PrincipalSID", default, deserialize_with = "nullable")]
    pub principal_sid: String,
    #[serde(rename = "PrincipalType", default, deserialize_with = "nullable")]
    pub principal_type: String,
    #[serde(rename = "RightName", default, deserialize_with = "nullable")]
    pub right_name: String,
    #[serde(rename = "IsInherited", default, deserialize_with = "nullable")]
    pub is_inherited: bool,
}

#[derive(Debug, Deserialize)]
pub struct RawSession {
    #[serde(rename = "UserSID", default)]
    pub user_sid: Option<String>,
    #[serde(rename = "ComputerSID", default)]
    pub computer_sid: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawLocalGroup {
    #[serde(default, deserialize_with = "nullable")]
    pub object_identifier: String,
    #[serde(default, deserialize_with = "nullable")]
    pub name: String,
    #[serde(default, deserialize_with = "capped_vec")]
    pub results: Vec<TypedRef>,
    #[serde(default)]
    pub collected: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct RawLink {
    #[serde(rename = "GUID", default, deserialize_with = "nullable")]
    pub guid: String,
    #[serde(rename = "IsEnforced", default, deserialize_with = "nullable")]
    pub is_enforced: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawTrust {
    #[serde(default, deserialize_with = "nullable")]
    pub target_domain_sid: String,
    #[serde(default)]
    pub target_domain_name: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    pub is_transitive: bool,
    #[serde(default, deserialize_with = "nullable")]
    pub sid_filtering_enabled: bool,
    #[serde(default, deserialize_with = "value")]
    pub trust_direction: Value,
    #[serde(default, deserialize_with = "value")]
    pub trust_type: Value,
    /// The raw trustAttributes (RustHound-CE, newer SharpHound).
    #[serde(default, deserialize_with = "value")]
    pub trust_attributes: Value,
}

impl RawTrust {
    /// Older collectors emit enum ordinals, newer ones emit names.
    fn enum_name(v: &Value, names: &[&str]) -> String {
        match v {
            Value::Number(n) => n
                .as_u64()
                .and_then(|i| names.get(i as usize))
                .unwrap_or(&"Unknown")
                .to_string(),
            Value::String(s) => s.clone(),
            _ => "Unknown".into(),
        }
    }

    pub fn direction(&self) -> String {
        Self::enum_name(
            &self.trust_direction,
            &["Disabled", "Inbound", "Outbound", "Bidirectional"],
        )
    }

    pub fn kind(&self) -> String {
        Self::enum_name(
            &self.trust_type,
            &["ParentChild", "CrossLink", "Forest", "External", "Unknown"],
        )
    }

    /// Whether SID filtering protects this trust. From `TrustAttributes` when
    /// the collector gives them, since RustHound-CE marks every forest trust
    /// as filtered even when SID history is enabled across it; otherwise the
    /// collector's `SidFilteringEnabled`.
    ///
    /// "Not filtered" across forests means weakly filtered: every trust
    /// between forests still drops RIDs under 1000, Enterprise Domain
    /// Controllers (S-1-5-9) and the built-in SIDs (MS-PAC 4.1.2.2).
    ///
    /// - QUARANTINED_DOMAIN (0x4): filtered.
    /// - FOREST_TRANSITIVE (0x8): filtered unless TREAT_AS_EXTERNAL (0x40),
    ///   which `netdom trust /enablesidhistory:yes` sets and which lets SIDs
    ///   from outside the trusted forest (the trusting forest's own
    ///   included) through when their RID is 1000 or above.
    /// - Otherwise: within a forest (0x20), no SID filtering applies; an
    ///   external trust not quarantined filters only RIDs under 1000,
    ///   S-1-5-9 and the built-in SIDs.
    pub fn sid_filtering(&self) -> bool {
        const QUARANTINED_DOMAIN: u64 = 0x4;
        const FOREST_TRANSITIVE: u64 = 0x8;
        const TREAT_AS_EXTERNAL: u64 = 0x40;
        let Some(attrs) = self.trust_attributes.as_u64() else {
            return self.sid_filtering_enabled;
        };
        if attrs & QUARANTINED_DOMAIN != 0 {
            true
        } else if attrs & FOREST_TRANSITIVE != 0 {
            attrs & TREAT_AS_EXTERNAL == 0
        } else {
            // Within a forest (nothing filtered), or an external trust that
            // is not quarantined (only RIDs under 1000 and built-ins).
            false
        }
    }

    /// Whether the trust uses selective authentication (CROSS_ORGANIZATION,
    /// 0x10): only accounts granted "Allowed to authenticate" on a resource
    /// can use it. `None` when the collector gives no `TrustAttributes`.
    pub fn selective_auth(&self) -> Option<bool> {
        const CROSS_ORGANIZATION: u64 = 0x10;
        self.trust_attributes
            .as_u64()
            .map(|attrs| attrs & CROSS_ORGANIZATION != 0)
    }

    /// Intra-forest trusts: the forest, not the domain, is the security boundary.
    pub fn is_same_forest(&self) -> bool {
        is_same_forest_type(&self.kind())
    }
}

/// Whether a trust of this type (as [`RawTrust::kind`] names it) stays
/// inside one forest.
pub fn is_same_forest_type(kind: &str) -> bool {
    matches!(
        kind.to_ascii_lowercase().as_str(),
        "parentchild" | "crosslink" | "treeroot" | "shortcut"
    )
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawObject {
    #[serde(default, deserialize_with = "nullable")]
    pub object_identifier: String,
    #[serde(default, deserialize_with = "known_properties")]
    pub properties: Map<String, Value>,
    #[serde(default, deserialize_with = "capped_vec")]
    pub aces: Vec<RawAce>,
    #[serde(default, deserialize_with = "capped_vec")]
    pub members: Vec<TypedRef>,
    #[serde(rename = "PrimaryGroupSID", default)]
    pub primary_group_sid: Option<String>,
    #[serde(default, deserialize_with = "capped_vec")]
    pub allowed_to_delegate: Vec<TypedRef>,
    #[serde(default, deserialize_with = "capped_vec")]
    pub allowed_to_act: Vec<TypedRef>,
    #[serde(rename = "HasSIDHistory", default, deserialize_with = "capped_vec")]
    pub has_sid_history: Vec<TypedRef>,
    #[serde(default, deserialize_with = "nullable")]
    pub sessions: ResultSet<RawSession>,
    #[serde(default, deserialize_with = "nullable")]
    pub privileged_sessions: ResultSet<RawSession>,
    #[serde(default, deserialize_with = "nullable")]
    pub registry_sessions: ResultSet<RawSession>,
    #[serde(default, deserialize_with = "nullable")]
    pub local_admins: ResultSet<TypedRef>,
    #[serde(default, deserialize_with = "nullable")]
    pub remote_desktop_users: ResultSet<TypedRef>,
    #[serde(default, deserialize_with = "nullable")]
    pub dcom_users: ResultSet<TypedRef>,
    #[serde(rename = "PSRemoteUsers", default, deserialize_with = "nullable")]
    pub ps_remote_users: ResultSet<TypedRef>,
    #[serde(default, deserialize_with = "capped_vec")]
    pub local_groups: Vec<RawLocalGroup>,
    #[serde(default, deserialize_with = "capped_vec")]
    pub child_objects: Vec<TypedRef>,
    #[serde(default, deserialize_with = "capped_vec")]
    pub links: Vec<RawLink>,
    #[serde(default, deserialize_with = "capped_vec")]
    pub trusts: Vec<RawTrust>,
    #[serde(default)]
    pub contained_by: Option<TypedRef>,
    #[serde(default, deserialize_with = "nullable")]
    pub is_deleted: bool,
    #[serde(rename = "IsDC", default, deserialize_with = "nullable")]
    pub is_dc: bool,
    #[serde(rename = "DomainSID", default)]
    pub domain_sid: Option<String>,
    // AD CS
    #[serde(default)]
    pub hosting_computer: Option<String>,
    #[serde(rename = "CARegistryData", default)]
    pub ca_registry_data: Option<RawCaRegistry>,
    #[serde(default, deserialize_with = "capped_vec")]
    pub enabled_cert_templates: Vec<TypedRef>,
    #[serde(default, deserialize_with = "value_vec")]
    pub http_enrollment_endpoints: Vec<Value>,
    #[serde(default)]
    pub group_link: Option<TypedRef>,
    #[serde(rename = "DCRegistryData", default, deserialize_with = "opt_value")]
    pub dc_registry_data: Option<Value>,
    /// OUs and domains: local group memberships their linked GPOs set.
    #[serde(rename = "GPOChanges", default)]
    pub gpo_changes: Option<RawGpoChanges>,
}

/// Local groups set by Group Policy (Restricted Groups or Group Policy
/// Preferences) on the computers under an OU or domain, as SharpHound and
/// RustHound-CE write them.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawGpoChanges {
    #[serde(default, deserialize_with = "capped_vec")]
    pub local_admins: Vec<TypedRef>,
    #[serde(default, deserialize_with = "capped_vec")]
    pub remote_desktop_users: Vec<TypedRef>,
    #[serde(default, deserialize_with = "capped_vec")]
    pub dcom_users: Vec<TypedRef>,
    #[serde(rename = "PSRemoteUsers", default, deserialize_with = "capped_vec")]
    pub ps_remote_users: Vec<TypedRef>,
    #[serde(default, deserialize_with = "capped_vec")]
    pub affected_computers: Vec<TypedRef>,
}

/// Values SharpHound reads from the CA's registry. RustHound-CE emits
/// placeholders here, which the `*collected` properties let us detect.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawCaRegistry {
    #[serde(rename = "CASecurity", default)]
    pub ca_security: Option<RawCaSecurity>,
    #[serde(default)]
    pub enrollment_agent_restrictions: Option<RawRestrictions>,
    #[serde(default)]
    pub is_user_specifies_san_enabled: Option<RawRegistryBool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawCaSecurity {
    #[serde(default, deserialize_with = "capped_vec")]
    pub data: Vec<RawAce>,
    #[serde(default, deserialize_with = "nullable")]
    pub collected: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawRestrictions {
    #[serde(default, deserialize_with = "capped_vec")]
    pub restrictions: Vec<RawRestriction>,
    #[serde(default, deserialize_with = "nullable")]
    pub collected: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawRestriction {
    #[serde(default, deserialize_with = "nullable")]
    pub access_type: String,
    #[serde(default)]
    pub agent: Option<TypedRef>,
    #[serde(default)]
    pub template: Option<TypedRef>,
    #[serde(default, deserialize_with = "nullable")]
    pub all_templates: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawRegistryBool {
    #[serde(default)]
    pub value: Option<bool>,
    #[serde(default, deserialize_with = "nullable")]
    pub collected: bool,
}

#[cfg(test)]
mod tests {
    use super::RawTrust;

    fn trust(json: &str) -> RawTrust {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn sid_filtering_follows_trust_attributes() {
        // RustHound-CE says "filtered" for every forest trust.
        let rh = |attrs: u32| {
            trust(&format!(
                r#"{{"TrustAttributes":{attrs},"SidFilteringEnabled":true,"TrustType":"Forest"}}"#
            ))
            .sid_filtering()
        };
        assert!(rh(0x8), "forest trust");
        assert!(!rh(0x48), "forest trust with SID history (GOAD)");
        assert!(rh(0x4), "quarantined external trust");
        assert!(!rh(0x0), "external trust without quarantine");
        assert!(!rh(0x20), "within the forest");
        // Without attributes (SharpHound 2.3), the collector's flag.
        assert!(!trust(r#"{"SidFilteringEnabled":false}"#).sid_filtering());
        assert!(trust(r#"{"SidFilteringEnabled":true}"#).sid_filtering());
    }

    #[test]
    fn selective_auth_from_trust_attributes() {
        let attrs = |a: u32| trust(&format!(r#"{{"TrustAttributes":{a}}}"#)).selective_auth();
        assert_eq!(attrs(0x18), Some(true), "forest trust, selective");
        assert_eq!(attrs(0x8), Some(false), "forest trust, forest-wide");
        // SharpHound 2.3 gives no attributes: unknown, not "off".
        assert_eq!(trust("{}").selective_auth(), None);
    }
}
