use crate::model::{BaseRow, Hash};

/// One end's state for a path, after any hashing the engine decided to do.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// `None` only in `--fast` mode when the answer was not needed.
    pub hash: Option<Hash>,
    /// Differs from what the pair last agreed on.
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing to do.
    Noop,
    /// The content agrees; the archive row is stale.
    Adopt,
    /// Put the source's content at the destination.
    Copy,
    /// The source does not have it; remove it from the destination.
    Delete,
    /// Nothing to do, but the user should know why.
    Skip(&'static str),
}

fn same_content(a: Option<Hash>, b: Option<Hash>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x == y)
}

/// What to do about one path.
///
/// The source always wins: the destination is made to hold what the source
/// holds. The archive is the memory of the pair, so it says what changed since
/// the last run; when it says nothing, the content decides.
pub fn decide(
    source: Option<&Resolved>,
    destination: Option<&Resolved>,
    base: Option<&BaseRow>,
    delete_extraneous: bool,
) -> Verdict {
    match (source, destination) {
        // The source has it, the destination does not: put it there.
        (Some(_), None) => Verdict::Copy,
        // The source does not have it: the destination must not keep it.
        (None, Some(_)) => {
            if delete_extraneous {
                Verdict::Delete
            } else {
                Verdict::Skip("absent on the source side (pass --delete to remove)")
            }
        }
        (None, None) => Verdict::Noop,
        (Some(s), Some(d)) => {
            if base.is_none() {
                // Nothing is known about this path yet: the content decides.
                return if same_content(s.hash, d.hash) {
                    Verdict::Adopt
                } else {
                    Verdict::Copy
                };
            }
            // The fast path: both ends still hold what the pair agreed on.
            if !s.changed && !d.changed {
                return Verdict::Noop;
            }
            // The source moved: the destination follows, whatever it holds.
            if s.changed {
                return Verdict::Copy;
            }
            // The source still holds what the pair agreed on, the destination
            // does not: the same content needs no transfer, only a fresh
            // archive row.
            if same_content(s.hash, d.hash) {
                Verdict::Adopt
            } else {
                Verdict::Copy
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Kind;

    fn res(hash: u8, changed: bool) -> Resolved {
        Resolved {
            hash: Some([hash; 32]),
            changed,
        }
    }

    fn unknown(changed: bool) -> Resolved {
        Resolved {
            hash: None,
            changed,
        }
    }

    fn base(hash: u8) -> BaseRow {
        BaseRow {
            kind: Kind::File,
            size: 10,
            mtime_source: 1,
            mtime_destination: 1,
            hash: [hash; 32],
        }
    }

    #[test]
    fn an_untouched_pair_does_nothing() {
        assert_eq!(
            decide(
                Some(&res(1, false)),
                Some(&res(1, false)),
                Some(&base(1)),
                false
            ),
            Verdict::Noop
        );
    }

    #[test]
    fn the_source_always_wins() {
        // The source changed: the destination follows.
        assert_eq!(
            decide(
                Some(&res(2, true)),
                Some(&res(1, false)),
                Some(&base(1)),
                false
            ),
            Verdict::Copy
        );
        // The destination changed on its own: the source still wins.
        assert_eq!(
            decide(
                Some(&res(1, false)),
                Some(&res(9, true)),
                Some(&base(1)),
                false
            ),
            Verdict::Copy
        );
        // Both changed: still the source that wins.
        assert_eq!(
            decide(
                Some(&res(2, true)),
                Some(&res(3, true)),
                Some(&base(1)),
                false
            ),
            Verdict::Copy
        );
    }

    #[test]
    fn equal_content_only_needs_a_fresh_archive_row() {
        // The same content on both sides, seen for the first time.
        assert_eq!(
            decide(Some(&res(1, false)), Some(&res(1, false)), None, false),
            Verdict::Adopt
        );
        // The source is unchanged, the destination was touched: same content.
        assert_eq!(
            decide(
                Some(&res(1, false)),
                Some(&res(1, true)),
                Some(&base(1)),
                false
            ),
            Verdict::Adopt
        );
        // The source is unchanged, the destination holds something else.
        assert_eq!(
            decide(
                Some(&res(1, false)),
                Some(&res(9, true)),
                Some(&base(1)),
                false
            ),
            Verdict::Copy
        );
    }

    #[test]
    fn a_path_the_destination_does_not_have_is_copied() {
        assert_eq!(
            decide(Some(&res(1, true)), None, None, false),
            Verdict::Copy
        );
        assert_eq!(
            decide(Some(&res(1, false)), None, Some(&base(1)), false),
            Verdict::Copy
        );
    }

    #[test]
    fn a_path_the_source_does_not_have_is_only_removed_on_request() {
        assert_eq!(
            decide(None, Some(&res(1, false)), Some(&base(1)), false),
            Verdict::Skip("absent on the source side (pass --delete to remove)")
        );
        assert_eq!(
            decide(None, Some(&res(1, false)), Some(&base(1)), true),
            Verdict::Delete
        );
        assert_eq!(decide(None, None, Some(&base(1)), true), Verdict::Noop);
    }

    #[test]
    fn fast_mode_never_needs_hashes_to_pick_a_direction() {
        assert_eq!(
            decide(
                Some(&unknown(true)),
                Some(&unknown(true)),
                Some(&base(1)),
                false
            ),
            Verdict::Copy
        );
        assert_eq!(
            decide(
                Some(&unknown(false)),
                Some(&unknown(true)),
                Some(&base(1)),
                false
            ),
            Verdict::Copy
        );
    }
}
