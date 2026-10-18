use crate::model::{BaseRow, Hash, Kind, Side};

/// One side's state for a path, after any hashing the engine decided to do.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub kind: Kind,
    pub size: u64,
    pub mtime_ns: i64,
    /// `None` only in `--fast` mode when the answer was not needed.
    pub hash: Option<Hash>,
    /// Differs from what both sides last agreed on.
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Already converged.
    Noop,
    /// Content agrees; the archive row is stale.
    Adopt,
    /// Copy the source side's content to the other side.
    CopyTo(Side),
    /// Both sides changed; keep both versions.
    Conflict,
    /// Remove the path on that side.
    DeleteAt(Side),
    /// The other side deleted it and this one changed it: keep the change.
    Resurrect(Side),
    /// Nothing to do, but the user should know why.
    Skip(&'static str),
}

fn same_content(a: Option<Hash>, b: Option<Hash>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x == y)
}

/// Two-way: the archive is the shared memory of the pair, so a change on one
/// side propagates and a change on both sides is a conflict.
pub fn two_way(
    local: Option<&Resolved>,
    remote: Option<&Resolved>,
    base: Option<&BaseRow>,
) -> Verdict {
    match (local, remote) {
        (Some(l), Some(r)) => match (l.changed, r.changed) {
            (false, false) => Verdict::Noop,
            (true, false) => Verdict::CopyTo(Side::Remote),
            (false, true) => Verdict::CopyTo(Side::Local),
            (true, true) => {
                if same_content(l.hash, r.hash) {
                    Verdict::Adopt
                } else {
                    Verdict::Conflict
                }
            }
        },
        (Some(l), None) => match base {
            None => Verdict::CopyTo(Side::Remote),
            Some(_) => {
                if l.changed {
                    Verdict::Resurrect(Side::Remote)
                } else {
                    Verdict::DeleteAt(Side::Local)
                }
            }
        },
        (None, Some(r)) => match base {
            None => Verdict::CopyTo(Side::Local),
            Some(_) => {
                if r.changed {
                    Verdict::Resurrect(Side::Local)
                } else {
                    Verdict::DeleteAt(Side::Remote)
                }
            }
        },
        (None, None) => Verdict::Noop,
    }
}

/// One-way: the source always wins; the target is only ever written to.
pub fn one_way(
    source: Option<&Resolved>,
    target: Option<&Resolved>,
    target_side: Side,
    delete_extraneous: bool,
) -> Verdict {
    match (source, target) {
        (Some(s), Some(t)) => {
            let settled = !s.changed && !t.changed;
            if settled || same_content(s.hash, t.hash) {
                Verdict::Noop
            } else {
                Verdict::CopyTo(target_side)
            }
        }
        (Some(_), None) => Verdict::CopyTo(target_side),
        (None, Some(_)) => {
            if delete_extraneous {
                Verdict::DeleteAt(target_side)
            } else {
                Verdict::Skip("absent on the source side (pass --delete to remove)")
            }
        }
        (None, None) => Verdict::Noop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Kind;

    fn res(hash: u8, changed: bool) -> Resolved {
        Resolved {
            kind: Kind::File,
            size: 10,
            mtime_ns: 1,
            hash: Some([hash; 32]),
            changed,
        }
    }

    fn unknown(changed: bool) -> Resolved {
        Resolved {
            kind: Kind::File,
            size: 10,
            mtime_ns: 1,
            hash: None,
            changed,
        }
    }

    fn base(hash: u8) -> BaseRow {
        BaseRow {
            kind: Kind::File,
            size: 10,
            mtime_local: 1,
            mtime_remote: 1,
            hash: [hash; 32],
        }
    }

    #[test]
    fn converged_paths_do_nothing() {
        assert_eq!(
            two_way(Some(&res(1, false)), Some(&res(1, false)), Some(&base(1))),
            Verdict::Noop
        );
    }

    #[test]
    fn single_sided_changes_propagate_both_directions() {
        assert_eq!(
            two_way(Some(&res(2, true)), Some(&res(1, false)), Some(&base(1))),
            Verdict::CopyTo(Side::Remote)
        );
        assert_eq!(
            two_way(Some(&res(1, false)), Some(&res(2, true)), Some(&base(1))),
            Verdict::CopyTo(Side::Local)
        );
    }

    #[test]
    fn concurrent_changes_conflict_unless_identical() {
        assert_eq!(
            two_way(Some(&res(2, true)), Some(&res(3, true)), Some(&base(1))),
            Verdict::Conflict
        );
        assert_eq!(
            two_way(Some(&res(2, true)), Some(&res(2, true)), Some(&base(1))),
            Verdict::Adopt
        );
    }

    #[test]
    fn deletion_propagates_only_when_the_survivor_did_not_change() {
        // remote deleted, local untouched -> delete locally
        assert_eq!(
            two_way(Some(&res(1, false)), None, Some(&base(1))),
            Verdict::DeleteAt(Side::Local)
        );
        // remote deleted, local edited -> keep the edit
        assert_eq!(
            two_way(Some(&res(2, true)), None, Some(&base(1))),
            Verdict::Resurrect(Side::Remote)
        );
        // never seen before -> brand new file
        assert_eq!(
            two_way(Some(&res(1, true)), None, None),
            Verdict::CopyTo(Side::Remote)
        );
    }

    #[test]
    fn one_way_ignores_target_edits_and_only_deletes_when_asked() {
        assert_eq!(
            one_way(
                Some(&res(1, false)),
                Some(&res(9, true)),
                Side::Remote,
                true
            ),
            Verdict::CopyTo(Side::Remote)
        );
        assert_eq!(
            one_way(
                Some(&res(1, false)),
                Some(&res(1, false)),
                Side::Remote,
                true
            ),
            Verdict::Noop
        );
        assert_eq!(
            one_way(None, Some(&res(1, false)), Side::Remote, false),
            Verdict::Skip("absent on the source side (pass --delete to remove)")
        );
        assert_eq!(
            one_way(None, Some(&res(1, false)), Side::Remote, true),
            Verdict::DeleteAt(Side::Remote)
        );
        assert_eq!(
            one_way(Some(&res(1, true)), None, Side::Remote, false),
            Verdict::CopyTo(Side::Remote)
        );
    }

    #[test]
    fn fast_mode_never_needs_hashes_to_pick_a_direction() {
        assert_eq!(
            one_way(
                Some(&unknown(true)),
                Some(&unknown(true)),
                Side::Local,
                false
            ),
            Verdict::CopyTo(Side::Local)
        );
    }
}
