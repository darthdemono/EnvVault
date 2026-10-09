//! A small line diff for rendered config files (Phase 35).
//!
//! Exists once, in Rust: the CLI, the server and the app all ask for a diff
//! instead of each carrying one, so the three cannot disagree about what changed.
//!
//! Strategy: strip the common head and tail, then a longest-common-subsequence
//! table over what is left. Rendered configs are tens to a few thousand lines
//! and differ in a few places, so the middle is small. When it is not
//! (`MAX_CELLS`), the middle is reported as one deletion and one insertion
//! rather than spending quadratic memory; the output stays correct, only less
//! minimal. // ponytail: LCS table, switch to Myers O(ND) if a real config ever
//! hits the cell ceiling.

/// Largest `n * m` the LCS table may reach (16 MB of `u32`).
pub const MAX_CELLS: usize = 4_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op<'a> {
    Equal(&'a str),
    Delete(&'a str),
    Insert(&'a str),
}

/// The edit script turning `a` into `b`, line by line.
pub fn diff_ops<'a>(a: &'a str, b: &'a str) -> Vec<Op<'a>> {
    let av: Vec<&str> = a.lines().collect();
    let bv: Vec<&str> = b.lines().collect();
    let head = av.iter().zip(&bv).take_while(|(x, y)| x == y).count();
    let tail = av[head..]
        .iter()
        .rev()
        .zip(bv[head..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let am = &av[head..av.len() - tail];
    let bm = &bv[head..bv.len() - tail];

    let mut ops: Vec<Op> = av[..head].iter().map(|l| Op::Equal(l)).collect();
    if am.len().saturating_mul(bm.len()) > MAX_CELLS {
        ops.extend(am.iter().map(|l| Op::Delete(l)));
        ops.extend(bm.iter().map(|l| Op::Insert(l)));
    } else {
        let (n, m) = (am.len(), bm.len());
        // lcs[i][j] = length of the LCS of am[i..] and bm[j..]
        let mut lcs = vec![0u32; (n + 1) * (m + 1)];
        let at = |i: usize, j: usize| i * (m + 1) + j;
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                lcs[at(i, j)] = if am[i] == bm[j] {
                    lcs[at(i + 1, j + 1)] + 1
                } else {
                    lcs[at(i + 1, j)].max(lcs[at(i, j + 1)])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < n && j < m {
            if am[i] == bm[j] {
                ops.push(Op::Equal(am[i]));
                i += 1;
                j += 1;
            } else if lcs[at(i + 1, j)] >= lcs[at(i, j + 1)] {
                ops.push(Op::Delete(am[i]));
                i += 1;
            } else {
                ops.push(Op::Insert(bm[j]));
                j += 1;
            }
        }
        ops.extend(am[i..].iter().map(|l| Op::Delete(l)));
        ops.extend(bm[j..].iter().map(|l| Op::Insert(l)));
    }
    ops.extend(av[av.len() - tail..].iter().map(|l| Op::Equal(l)));
    ops
}

/// Counts of changed lines: `(added, removed)`.
pub fn stat(ops: &[Op]) -> (usize, usize) {
    ops.iter().fold((0, 0), |(a, r), o| match o {
        Op::Insert(_) => (a + 1, r),
        Op::Delete(_) => (a, r + 1),
        Op::Equal(_) => (a, r),
    })
}

/// A unified diff with `context` lines around each change. Empty string when
/// the two sides are identical.
pub fn unified(a_label: &str, b_label: &str, a: &str, b: &str, context: usize) -> String {
    let ops = diff_ops(a, b);
    if stat(&ops) == (0, 0) {
        return String::new();
    }
    // Index of each op's line in a and b (1-based), to head the hunks.
    let mut pos = Vec::with_capacity(ops.len());
    let (mut la, mut lb) = (1usize, 1usize);
    for o in &ops {
        pos.push((la, lb));
        match o {
            Op::Equal(_) => {
                la += 1;
                lb += 1;
            }
            Op::Delete(_) => la += 1,
            Op::Insert(_) => lb += 1,
        }
    }
    let changed: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, o)| !matches!(o, Op::Equal(_)))
        .map(|(i, _)| i)
        .collect();

    // Merge changes whose context windows touch into one hunk.
    let mut hunks: Vec<(usize, usize)> = Vec::new();
    for &c in &changed {
        let lo = c.saturating_sub(context);
        let hi = (c + context + 1).min(ops.len());
        match hunks.last_mut() {
            Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
            _ => hunks.push((lo, hi)),
        }
    }

    let mut out = format!("--- {a_label}\n+++ {b_label}\n");
    for (lo, hi) in hunks {
        let slice = &ops[lo..hi];
        let a_len = slice.iter().filter(|o| !matches!(o, Op::Insert(_))).count();
        let b_len = slice.iter().filter(|o| !matches!(o, Op::Delete(_))).count();
        let (sa, sb) = pos[lo];
        out.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            if a_len == 0 { sa - 1 } else { sa },
            a_len,
            if b_len == 0 { sb - 1 } else { sb },
            b_len
        ));
        for o in slice {
            let (p, l) = match o {
                Op::Equal(l) => (' ', l),
                Op::Delete(l) => ('-', l),
                Op::Insert(l) => ('+', l),
            };
            out.push(p);
            out.push_str(l);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rebuild(ops: &[Op], side_a: bool) -> String {
        let mut v = Vec::new();
        for o in ops {
            match (o, side_a) {
                (Op::Equal(l), _) | (Op::Delete(l), true) | (Op::Insert(l), false) => v.push(*l),
                _ => {}
            }
        }
        v.join("\n")
    }

    #[test]
    fn identical_text_has_no_diff() {
        assert_eq!(unified("a", "b", "x\ny\n", "x\ny\n", 3), "");
    }

    #[test]
    fn a_changed_line_shows_as_a_delete_and_an_insert_with_context() {
        let d = unified("old", "new", "a\nb\nc\nd\ne\n", "a\nb\nX\nd\ne\n", 1);
        assert_eq!(d, "--- old\n+++ new\n@@ -2,3 +2,3 @@\n b\n-c\n+X\n d\n");
    }

    #[test]
    fn distant_changes_make_separate_hunks_and_near_ones_merge() {
        let a: String = (1..=20).map(|i| format!("l{i}\n")).collect();
        let far = a.replace("l2\n", "L2\n").replace("l19\n", "L19\n");
        assert_eq!(unified("a", "b", &a, &far, 1).matches("@@ -").count(), 2);
        let near = a.replace("l5\n", "L5\n").replace("l7\n", "L7\n");
        assert_eq!(unified("a", "b", &a, &near, 1).matches("@@ -").count(), 1);
    }

    #[test]
    fn pure_additions_and_removals_head_their_hunks_correctly() {
        assert_eq!(
            unified("a", "b", "", "x\ny\n", 3),
            "--- a\n+++ b\n@@ -0,0 +1,2 @@\n+x\n+y\n"
        );
        assert_eq!(
            unified("a", "b", "x\ny\n", "", 3),
            "--- a\n+++ b\n@@ -1,2 +0,0 @@\n-x\n-y\n"
        );
    }

    #[test]
    fn the_script_always_reproduces_both_sides() {
        let cases = [
            ("a\nb\nc", "a\nc"),
            ("", "a"),
            ("a", ""),
            ("a\nb\nc\nd", "d\nc\nb\na"),
            ("x\nx\nx", "x\nx"),
            ("1\n2\n3\n4\n5\n6", "1\n3\n2\n4\n6\n5\n7"),
        ];
        for (a, b) in cases {
            let ops = diff_ops(a, b);
            assert_eq!(rebuild(&ops, true), a, "side a of {a:?} -> {b:?}");
            assert_eq!(rebuild(&ops, false), b, "side b of {a:?} -> {b:?}");
        }
    }

    #[test]
    fn the_diff_is_minimal_for_a_single_insertion() {
        let ops = diff_ops("a\nb\nc", "a\nb\nNEW\nc");
        assert_eq!(stat(&ops), (1, 0));
    }

    #[test]
    fn past_the_cell_ceiling_the_middle_is_replaced_whole_but_still_correct() {
        let a: String = (0..2100).map(|i| format!("a{i}\n")).collect();
        let b: String = (0..2100).map(|i| format!("b{i}\n")).collect();
        let ops = diff_ops(&a, &b);
        assert_eq!(stat(&ops), (2100, 2100));
        assert_eq!(rebuild(&ops, true), a.trim_end());
    }
}
