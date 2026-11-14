//! Helpers for Windows security identifiers as they appear in BloodHound data.
//!
//! SharpHound and RustHound-CE prefix well-known SIDs with the domain name so they
//! stay unique across a forest, e.g. `CONTOSO.LOCAL-S-1-5-32-544` for the builtin
//! Administrators group of CONTOSO.LOCAL.

/// Splits a domain-prefixed identifier into `(Some(domain), sid)`.
pub fn split_prefixed(id: &str) -> (Option<&str>, &str) {
    match id.find("-S-1-") {
        Some(p) if p > 0 => (Some(&id[..p]), &id[p + 1..]),
        _ => (None, id),
    }
}

fn domain_parts(id: &str) -> Option<Vec<&str>> {
    let (_, sid) = split_prefixed(id);
    let parts: Vec<&str> = sid.split('-').collect();
    (sid.starts_with("S-1-5-21-") && parts.len() == 8).then_some(parts)
}

/// The relative identifier of a domain principal (`S-1-5-21-a-b-c-RID`).
pub fn domain_rid(id: &str) -> Option<u32> {
    domain_parts(id)?[7].parse().ok()
}

/// The domain SID that a domain principal belongs to.
pub fn domain_sid_of(id: &str) -> Option<String> {
    // The SID up to its last part, sliced: this runs for every object.
    let (_, sid) = split_prefixed(id);
    let dashes = sid.bytes().filter(|&b| b == b'-').count();
    (sid.starts_with("S-1-5-21-") && dashes == 7)
        .then(|| sid[..sid.rfind('-').unwrap_or(0)].to_owned())
}

/// The RID suffix of a computer-local group, e.g. `...-1001-544` -> 544.
pub fn local_group_rid(id: &str) -> Option<u32> {
    id.rsplit('-').next()?.parse().ok()
}

pub fn well_known_name(id: &str) -> Option<&'static str> {
    let (_, sid) = split_prefixed(id);
    let name = match sid {
        "S-1-1-0" => "EVERYONE",
        "S-1-5-11" => "AUTHENTICATED USERS",
        "S-1-5-9" => "ENTERPRISE DOMAIN CONTROLLERS",
        "S-1-5-32-544" => "ADMINISTRATORS",
        "S-1-5-32-545" => "USERS",
        "S-1-5-32-548" => "ACCOUNT OPERATORS",
        "S-1-5-32-549" => "SERVER OPERATORS",
        "S-1-5-32-550" => "PRINT OPERATORS",
        "S-1-5-32-551" => "BACKUP OPERATORS",
        "S-1-5-32-555" => "REMOTE DESKTOP USERS",
        "S-1-5-32-580" => "REMOTE MANAGEMENT USERS",
        _ => match domain_rid(id)? {
            500 => "ADMINISTRATOR",
            502 => "KRBTGT",
            512 => "DOMAIN ADMINS",
            513 => "DOMAIN USERS",
            515 => "DOMAIN COMPUTERS",
            516 => "DOMAIN CONTROLLERS",
            518 => "SCHEMA ADMINS",
            519 => "ENTERPRISE ADMINS",
            526 => "KEY ADMINS",
            527 => "ENTERPRISE KEY ADMINS",
            _ => return None,
        },
    };
    Some(name)
}

/// A readable name for an object we only know by identifier.
pub fn display_name(id: &str) -> String {
    match (well_known_name(id), split_prefixed(id).0, domain_sid_of(id)) {
        (Some(n), Some(domain), _) => format!("{n}@{domain}"),
        (Some(n), None, Some(dsid)) => format!("{n}@{dsid}"),
        (Some(n), None, None) => n.to_string(),
        (None, ..) => id.to_string(),
    }
}

/// Groups whose membership is implicit (every authenticated principal) and
/// therefore never listed by collectors.
pub fn is_implicit_group(id: &str) -> bool {
    matches!(split_prefixed(id), (Some(_), "S-1-1-0" | "S-1-5-11"))
}

/// Groups that contain (nearly) every principal. Granting them anything is
/// granting it to everyone, so they must never be absorbed into Tier Zero.
pub fn is_broad_group(id: &str) -> bool {
    let (_, sid) = split_prefixed(id);
    matches!(sid, "S-1-1-0" | "S-1-5-11" | "S-1-5-32-545")
        || matches!(domain_rid(id), Some(513 | 515))
}

/// Why an identifier is Tier Zero by definition, if it is.
pub fn tier_zero_reason(id: &str) -> Option<&'static str> {
    let (_, sid) = split_prefixed(id);
    match sid {
        "S-1-5-9" => Some("Enterprise Domain Controllers"),
        "S-1-5-32-544" => Some("Builtin Administrators"),
        "S-1-5-32-548" => Some("Account Operators"),
        "S-1-5-32-549" => Some("Server Operators"),
        "S-1-5-32-550" => Some("Print Operators"),
        "S-1-5-32-551" => Some("Backup Operators"),
        _ => match domain_rid(id)? {
            500 => Some("Built-in domain Administrator account"),
            502 => Some("krbtgt account"),
            512 => Some("Domain Admins"),
            516 => Some("Domain Controllers"),
            517 => Some("Cert Publishers"),
            518 => Some("Schema Admins"),
            519 => Some("Enterprise Admins"),
            526 => Some("Key Admins"),
            527 => Some("Enterprise Key Admins"),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_and_domain_sids() {
        assert_eq!(
            split_prefixed("CONTOSO.LOCAL-S-1-5-32-544"),
            (Some("CONTOSO.LOCAL"), "S-1-5-32-544")
        );
        assert_eq!(
            split_prefixed("S-1-5-21-1-2-3-512"),
            (None, "S-1-5-21-1-2-3-512")
        );
        assert_eq!(domain_rid("S-1-5-21-1-2-3-512"), Some(512));
        assert_eq!(domain_rid("S-1-5-21-1-2-3"), None);
        assert_eq!(domain_rid("S-1-5-21-1-2-3-1001-544"), None);
        assert_eq!(
            domain_sid_of("S-1-5-21-1-2-3-512").as_deref(),
            Some("S-1-5-21-1-2-3")
        );
        assert_eq!(
            domain_sid_of("CONTOSO.LOCAL-S-1-5-21-1-2-3-512").as_deref(),
            Some("S-1-5-21-1-2-3")
        );
        assert_eq!(domain_sid_of("S-1-5-21-1-2-3-1001-544"), None);
        assert_eq!(domain_sid_of("S-1-5-21-1-2-3"), None);
        assert_eq!(domain_sid_of("S-1-5-32-1-2-3-544"), None);
        assert_eq!(
            display_name("CONTOSO.LOCAL-S-1-5-11"),
            "AUTHENTICATED USERS@CONTOSO.LOCAL"
        );
        assert!(is_implicit_group("CONTOSO.LOCAL-S-1-1-0"));
        assert!(is_broad_group("S-1-5-21-1-2-3-513"));
        assert!(is_broad_group("CONTOSO.LOCAL-S-1-5-11"));
        assert!(!is_broad_group("S-1-5-21-1-2-3-512"));
        assert!(tier_zero_reason("S-1-5-21-1-2-3-519").is_some());
        assert!(tier_zero_reason("S-1-5-21-1-2-3-513").is_none());
    }
}
