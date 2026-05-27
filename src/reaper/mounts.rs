//! Parse `/proc/self/mountinfo` and decode octal-escaped path characters.
//! Pure functions on `&str` — no I/O.

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub mountpoint: PathBuf,
}

/// Parse mountinfo content; return entries whose mountpoint is `root` or
/// any path below it, sorted deepest-first.
pub fn collect_mounts_under(root: &std::path::Path, mountinfo: &str) -> Vec<MountEntry> {
    let mut out: Vec<MountEntry> = mountinfo
        .lines()
        .filter_map(parse_line)
        .filter(|m| m.mountpoint == root || m.mountpoint.starts_with(root))
        .collect();
    // Deepest-first by component count so we never try to unmount a
    // parent before its children.
    out.sort_by(|a, b| {
        b.mountpoint
            .components()
            .count()
            .cmp(&a.mountpoint.components().count())
    });
    out
}

/// Parse a single mountinfo line. Format (proc(5) / mountinfo(5)):
///   36 35 98:0 /mnt1 /mnt2 rw,noatime ...
/// The mountpoint is field index 4 (zero-based), separated by single
/// spaces. We decode `\\NNN` octal escapes per mountinfo(5):
///   \040 = space, \011 = tab, \012 = newline, \134 = backslash.
fn parse_line(line: &str) -> Option<MountEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 5 {
        return None;
    }
    let mp = decode_octal_escapes(fields[4]);
    Some(MountEntry {
        mountpoint: PathBuf::from(mp),
    })
}

fn decode_octal_escapes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
        {
            let digits = std::str::from_utf8(&bytes[i + 1..i + 4]).unwrap_or("0");
            if let Ok(v) = u8::from_str_radix(digits, 8) {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const SAMPLE: &str = "\
36 35 98:0 / /var/lib/kobe/leases/A/kubelets/podX/vol1 rw -
37 35 98:0 / /var/lib/kobe/leases/A/kubelets/podX/vol2 rw -
38 35 98:0 / /var/lib/kobe/leases/A/x rw -
39 35 98:0 / /unrelated rw -
";

    #[test]
    fn collect_mounts_under_returns_only_subtree_deepest_first() {
        let root = Path::new("/var/lib/kobe/leases/A");
        let got = collect_mounts_under(root, SAMPLE);
        assert_eq!(got.len(), 3);
        // Deepest first: vol1 / vol2 have more components than x.
        // Full paths: /var/lib/kobe/leases/A/kubelets/podX/vol{1,2} = 9 components
        //             /var/lib/kobe/leases/A/x = 7 components
        let depths: Vec<usize> = got
            .iter()
            .map(|m| m.mountpoint.components().count())
            .collect();
        assert_eq!(depths, vec![9, 9, 7]);
        // The two depth-7 mounts must both be present (order between
        // them not asserted).
        let set: std::collections::HashSet<_> = got.iter().map(|m| m.mountpoint.clone()).collect();
        assert!(set.contains(Path::new("/var/lib/kobe/leases/A/kubelets/podX/vol1")));
        assert!(set.contains(Path::new("/var/lib/kobe/leases/A/kubelets/podX/vol2")));
        assert!(set.contains(Path::new("/var/lib/kobe/leases/A/x")));
    }

    #[test]
    fn collect_mounts_under_empty_returns_empty() {
        let root = Path::new("/var/lib/kobe/leases/A");
        assert!(collect_mounts_under(root, "").is_empty());
    }

    #[test]
    fn collect_mounts_decodes_octal_escapes() {
        // mountpoint with a space encoded as \040
        let line = "36 35 98:0 / /var/lib/kobe/leases/A/has\\040space rw -\n";
        let root = Path::new("/var/lib/kobe/leases/A");
        let got = collect_mounts_under(root, line);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].mountpoint,
            Path::new("/var/lib/kobe/leases/A/has space")
        );
    }

    #[test]
    fn parse_line_rejects_short_lines() {
        assert!(parse_line("short").is_none());
    }
}
