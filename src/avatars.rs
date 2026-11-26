//! The ten built-in agent avatars: small SVG files compiled into the
//! binary and served at `/admin/avatars/<id>.svg`. An agent without a
//! chosen avatar gets a stable one derived from its name.

/// Every avatar, as (id, SVG). The ids are what the registry stores.
pub const AVATARS: &[(&str, &str)] = &[
    ("orbit", include_str!("../assets/avatars/orbit.svg")),
    ("comet", include_str!("../assets/avatars/comet.svg")),
    ("nova", include_str!("../assets/avatars/nova.svg")),
    ("prism", include_str!("../assets/avatars/prism.svg")),
    ("wave", include_str!("../assets/avatars/wave.svg")),
    ("ember", include_str!("../assets/avatars/ember.svg")),
    ("lattice", include_str!("../assets/avatars/lattice.svg")),
    ("crescent", include_str!("../assets/avatars/crescent.svg")),
    ("pulsar", include_str!("../assets/avatars/pulsar.svg")),
    ("hexa", include_str!("../assets/avatars/hexa.svg")),
];

/// The avatar ids, in the order the pickers show them.
pub fn ids() -> Vec<&'static str> {
    AVATARS.iter().map(|(id, _)| *id).collect()
}

/// Whether `id` names a built-in avatar.
pub fn is_known(id: &str) -> bool {
    AVATARS.iter().any(|(known, _)| *known == id)
}

/// The SVG of one avatar.
pub fn svg(id: &str) -> Option<&'static str> {
    AVATARS
        .iter()
        .find(|(known, _)| *known == id)
        .map(|(_, svg)| *svg)
}

/// The avatar an agent shows when nobody chose one: FNV-1a over the name's
/// UTF-8 bytes, modulo the number of avatars. The page computes the same
/// for names it has no record of, so both always agree.
pub fn default_for(name: &str) -> &'static str {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in name.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    AVATARS[(hash % AVATARS.len() as u32) as usize].0
}

/// The avatar an agent shows: its chosen one when that is a known id, else
/// the default for its name.
pub fn effective(name: &str, chosen: &str) -> &'static str {
    AVATARS
        .iter()
        .find(|(id, _)| *id == chosen)
        .map(|(id, _)| *id)
        .unwrap_or_else(|| default_for(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_distinct_avatars_that_are_svg() {
        assert_eq!(AVATARS.len(), 10);
        let mut seen = std::collections::HashSet::new();
        for (id, svg) in AVATARS {
            assert!(seen.insert(*id), "{id} twice");
            assert!(id.len() <= 10 && id.chars().all(|c| c.is_ascii_lowercase()));
            assert!(svg.trim_start().starts_with("<svg") && svg.trim_end().ends_with("</svg>"));
            // No text and no script inside an avatar.
            assert!(!svg.contains("<text") && !svg.contains("<script"));
        }
    }

    #[test]
    fn the_default_is_stable_and_known() {
        // The page's JavaScript computes the same FNV-1a: these values are
        // pinned so a change on either side is noticed.
        for (name, id) in [
            ("claude", "prism"),
            ("codex", "lattice"),
            ("cursor", "comet"),
            ("gemini", "pulsar"),
            ("shared", "nova"),
            ("ünï", "lattice"),
        ] {
            assert_eq!(default_for(name), id, "{name}");
        }
        assert_eq!(effective("claude", "nova"), "nova");
        assert_eq!(effective("claude", "nope"), default_for("claude"));
        assert_eq!(effective("claude", ""), default_for("claude"));
    }
}
