//! Attack path diagrams as inline SVG: one card per object, a labeled arrow per
//! relationship, left to right, wrapping onto new rows instead of shrinking.
//! Colors come from the page's CSS variables, so diagrams follow the theme.
//! Arrowheads are plain polygons (no <marker>), so many diagrams on one page
//! never share element IDs.

use std::borrow::Cow;
use std::fmt::Write;

use super::esc;
use crate::analysis::AttackPath;
use crate::model::NodeKind;

const WIDTH: f64 = 1000.0;
const PAD: f64 = 6.0;
const NODE_H: f64 = 58.0;
const ROW_GAP: f64 = 60.0;
/// Approximate advance per character: 13px semibold names (mostly upper
/// case) and 11px secondary lines.
const NAME_CHAR: f64 = 8.4;
const SUB_CHAR: f64 = 6.6;
const LABEL_CHAR: f64 = 7.8;
const NODE_MIN: f64 = 150.0;
const NODE_MAX: f64 = 300.0;
/// Space left of the text for the kind glyph.
const TEXT_X: f64 = 46.0;

struct Node {
    primary: String,
    sub: String,
    full: String,
    glyph: Cow<'static, str>,
    role: &'static str,
    w: f64,
    x: f64,
    y: f64,
}

fn glyph(kind: NodeKind) -> Cow<'static, str> {
    super::kind_icon_id(kind)
}

/// `JDOE@CONTOSO.LOCAL` -> ("JDOE", "CONTOSO.LOCAL"); computers split at the
/// first dot of their FQDN; domains keep their whole name.
fn split(name: &str, kind: NodeKind) -> (String, String) {
    if let Some((a, b)) = name.split_once('@') {
        return (a.to_string(), b.to_string());
    }
    if kind == NodeKind::Computer {
        if let Some((a, b)) = name.split_once('.') {
            return (a.to_string(), b.to_string());
        }
    }
    (name.to_string(), String::new())
}

fn fit(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let keep: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{keep}\u{2026}")
}

fn node(name: &str, kind: NodeKind, role: &'static str) -> Node {
    let (primary, domain) = split(name, kind);
    // An external kind reads as its pack's label ("Entra role").
    let kind_name = super::kind_label(kind);
    let sub = if domain.is_empty() {
        kind_name.to_string()
    } else {
        format!("{kind_name} \u{00b7} {domain}")
    };
    let want =
        (primary.chars().count() as f64 * NAME_CHAR).max(sub.chars().count() as f64 * SUB_CHAR);
    let w = (want + TEXT_X + 14.0).clamp(NODE_MIN, NODE_MAX);
    let room = w - TEXT_X - 10.0;
    Node {
        primary: fit(&primary, (room / NAME_CHAR) as usize),
        sub: fit(&sub, (room / SUB_CHAR) as usize),
        full: format!("{name} ({kind_name})"),
        glyph: glyph(kind),
        role,
        w,
        x: 0.0,
        y: 0.0,
    }
}

pub fn path_svg(p: &AttackPath) -> String {
    let Some(first) = p.steps.first() else {
        return String::new();
    };
    let last = p.steps.len();
    let mut nodes = vec![node(&first.from, first.from_kind, "start")];
    for (i, s) in p.steps.iter().enumerate() {
        nodes.push(node(
            &s.to,
            s.to_kind,
            if i + 1 == last { "target" } else { "mid" },
        ));
    }
    let labels: Vec<&str> = p.steps.iter().map(|s| s.edge.as_str()).collect();

    // Lay out left to right, starting a new row when the next hop won't fit.
    let mut wraps = vec![false; labels.len()];
    let (mut x, mut row) = (PAD, 0usize);
    for i in 0..nodes.len() {
        if i > 0 {
            let gap = (labels[i - 1].len() as f64 * LABEL_CHAR + 36.0).max(96.0);
            if x + gap + nodes[i].w > WIDTH - PAD {
                row += 1;
                x = PAD;
                wraps[i - 1] = true;
            } else {
                x += gap;
            }
        }
        nodes[i].x = x;
        nodes[i].y = PAD + row as f64 * (NODE_H + ROW_GAP);
        x += nodes[i].w;
    }
    let height = PAD * 2.0 + (row + 1) as f64 * NODE_H + row as f64 * ROW_GAP;
    // Size to the content so short paths render at natural size (and shrink
    // only on narrow screens) instead of sitting small on a wide canvas.
    let used = nodes.iter().map(|n| n.x + n.w).fold(0.0, f64::max) + PAD;

    let mut aria = format!("Attack path: {}", first.from);
    for s in &p.steps {
        let _ = write!(aria, ", {} {}", s.edge.as_str(), s.to);
    }
    let mut svg = String::new();
    let _ = write!(
        svg,
        r#"<svg class="pathviz" viewBox="0 0 {used:.0} {height:.0}" width="{used:.0}" height="{height:.0}" role="img" aria-label="{}" xmlns="http://www.w3.org/2000/svg">"#,
        esc(&aria)
    );

    for (i, label) in labels.iter().enumerate() {
        let (a, b) = (&nodes[i], &nodes[i + 1]);
        let label = esc(label);
        if wraps[i] {
            // Down from the end of one row, across, and down into the next.
            let (ax, bx) = (a.x + a.w / 2.0, b.x + b.w / 2.0);
            let (ay, by) = (a.y + NODE_H, b.y);
            let mid = ay + ROW_GAP / 2.0;
            let _ = write!(
                svg,
                r#"<path class="wire" d="M{ax:.1} {ay:.1} V{mid:.1} H{bx:.1} V{:.1}"/><polygon class="head" points="{bx:.1},{by:.1} {:.1},{:.1} {:.1},{:.1}"/><text class="elabel" x="{:.1}" y="{:.1}" text-anchor="middle">{label}</text>"#,
                by - 8.0,
                bx - 5.0,
                by - 8.0,
                bx + 5.0,
                by - 8.0,
                (ax + bx) / 2.0,
                mid - 7.0,
            );
        } else {
            let cy = a.y + NODE_H / 2.0;
            let (x1, x2) = (a.x + a.w, b.x);
            let _ = write!(
                svg,
                r#"<line class="wire" x1="{x1:.1}" y1="{cy:.1}" x2="{:.1}" y2="{cy:.1}"/><polygon class="head" points="{x2:.1},{cy:.1} {:.1},{:.1} {:.1},{:.1}"/><text class="elabel" x="{:.1}" y="{:.1}" text-anchor="middle">{label}</text>"#,
                x2 - 8.0,
                x2 - 8.0,
                cy - 5.0,
                x2 - 8.0,
                cy + 5.0,
                (x1 + x2) / 2.0,
                cy - 8.0,
            );
        }
    }

    for n in &nodes {
        let cy = n.y + NODE_H / 2.0;
        let _ = write!(
            svg,
            r##"<g class="node {role}"><title>{full}</title><rect x="{x:.1}" y="{y:.1}" width="{w:.1}" height="{NODE_H}" rx="10"/><circle class="kind" cx="{gx:.1}" cy="{cy:.1}" r="14"/><use class="glyph" href="#{glyph}" x="{ix:.1}" y="{iy:.1}" width="16" height="16"/><text class="nm" x="{tx:.1}" y="{ny:.1}">{primary}</text><text class="sub" x="{tx:.1}" y="{sy:.1}">{sub}</text></g>"##,
            role = n.role,
            full = esc(&n.full),
            x = n.x,
            y = n.y,
            w = n.w,
            gx = n.x + 24.0,
            ix = n.x + 16.0,
            iy = cy - 8.0,
            glyph = n.glyph,
            tx = n.x + TEXT_X,
            ny = cy - 3.0,
            sy = cy + 14.0,
            primary = esc(&n.primary),
            sub = esc(&n.sub),
        );
    }
    svg.push_str("</svg>");
    svg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::PathStep;
    use crate::model::EdgeKind;

    fn step(from: &str, fk: NodeKind, edge: EdgeKind, to: &str, tk: NodeKind) -> PathStep {
        PathStep {
            source: None,
            from: from.into(),
            from_kind: fk,
            edge,
            to: to.into(),
            to_kind: tk,
            backward: false,
        }
    }

    #[test]
    fn long_paths_wrap_and_text_is_escaped() {
        let names = [
            "A<B>@X.LOCAL",
            "GROUP ONE@X.LOCAL",
            "SRV01.X.LOCAL",
            "GROUP TWO@X.LOCAL",
            "DA@X.LOCAL",
            "X.LOCAL",
        ];
        let kinds = [
            NodeKind::User,
            NodeKind::Group,
            NodeKind::Computer,
            NodeKind::Group,
            NodeKind::User,
            NodeKind::Domain,
        ];
        let steps = (0..5)
            .map(|i| {
                step(
                    names[i],
                    kinds[i],
                    EdgeKind::WriteAccountRestrictions,
                    names[i + 1],
                    kinds[i + 1],
                )
            })
            .collect();
        let p = AttackPath {
            source: names[0].into(),
            target: names[5].into(),
            steps,
            edges: Vec::new(),
        };
        let svg = path_svg(&p);
        assert!(
            svg.contains(r#"class="wire" d="M"#),
            "a six-node path with long labels wraps"
        );
        assert!(!svg.contains("A<B>"));
        assert!(svg.contains("A&lt;B&gt;"));
        assert_eq!(svg.matches(r#"<g class="node"#).count(), 6);
        assert!(svg.contains(r#"class="node start""#) && svg.contains(r#"class="node target""#));
    }
}
