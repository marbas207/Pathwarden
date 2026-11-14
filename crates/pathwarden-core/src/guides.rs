//! Step-by-step remediation guides, one Markdown document per rule, compiled
//! into the binary so they ship with it. Source files live in `guides/`.

macro_rules! guides {
    ($($id:literal),* $(,)?) => {
        /// Rule IDs that have a guide.
        pub const ALL: &[&str] = &[$($id),*];

        /// The guide for a rule, as Markdown.
        pub fn guide(rule: &str) -> Option<&'static str> {
            match rule.trim().to_ascii_uppercase().as_str() {
                $($id => Some(include_str!(concat!("../guides/", $id, ".md"))),)*
                _ => None,
            }
        }
    };
}

guides!(
    "PW-001", "PW-002", "PW-003", "PW-004", "PW-005", "PW-006", "PW-007", "PW-008", "PW-009",
    "PW-010", "PW-011", "PW-012", "PW-013", "PW-014", "PW-015", "PW-016", "PW-017", "PW-018",
    "PW-019", "PW-020", "PW-021", "PW-022", "PW-023", "PW-025", "PW-026", "PW-027", "PW-028",
    "PW-029", "PW-030", "PW-031", "PW-032", "PW-033", "PW-034", "PW-035", "PW-036", "PW-037",
    "PW-038", "PW-039",
);

/// Sections every guide must have, in this order.
pub const SECTIONS: &[&str] = &[
    "## What this finding means",
    "## Why attackers care",
    "## Before you change anything",
    "## Fix",
    "## Verify",
    "## Rollback",
    "## References",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_has_a_complete_guide() {
        for rule in crate::findings::rules() {
            let text = guide(rule.id).unwrap_or_else(|| panic!("{} has no guide", rule.id));
            assert!(
                text.starts_with(&format!("# {}: ", rule.id)),
                "{} guide must start with its title",
                rule.id
            );
            let mut at = 0;
            for section in SECTIONS {
                let found = text[at..].find(section).unwrap_or_else(|| {
                    panic!(
                        "{} guide is missing '{section}' (or it is out of order)",
                        rule.id
                    )
                });
                at += found + section.len();
            }
        }
        assert_eq!(
            ALL.len(),
            crate::findings::rules().len(),
            "a guide without a rule"
        );
    }

    #[test]
    fn lookup_is_case_insensitive() {
        assert!(guide("pw-001").is_some());
        assert!(guide("PW-999").is_none());
    }
}
