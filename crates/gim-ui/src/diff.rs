//! Turning a recomputed list into minimal `VectorDiff`s.

use std::collections::HashMap;
use std::hash::Hash;

use eyeball_im::{ObservableVector, Vector, VectorDiff};

/// Makes `vector` equal to `new` in one batch: `Set` for an item whose key
/// stayed in place, `Remove` + `Insert` for a moved item, `Remove` /
/// `Insert` for gone / new items. Keys must be unique within each list.
pub(crate) fn update<T, K>(vector: &mut ObservableVector<T>, new: &[T], key: impl Fn(&T) -> K)
where
    T: Clone + PartialEq + 'static,
    K: Eq + Hash,
{
    let mut tx = vector.transaction();
    let new_index: HashMap<K, usize> = new.iter().enumerate().map(|(i, v)| (key(v), i)).collect();
    for i in (0..tx.len()).rev() {
        if !new_index.contains_key(&key(&tx[i])) {
            tx.remove(i);
        }
    }
    // Every remaining item is in `new`; positions before `i` are final.
    let mut i = 0;
    while i < new.len() {
        let wanted = key(&new[i]);
        if i < tx.len() {
            if key(&tx[i]) == wanted {
                if tx[i] != new[i] {
                    tx.set(i, new[i].clone());
                }
                i += 1;
                continue;
            }
            // Either the item at `i` moved down or the wanted one moved up;
            // move the one that travels further (on a tie, the wanted one).
            let down = new_index[&key(&tx[i])] - i;
            let up = (i + 1..tx.len())
                .find(|&j| key(&tx[j]) == wanted)
                .map(|j| (j, j - i));
            match up {
                Some((_, up)) if down > up => {
                    // Inserted again when its new position is reached.
                    tx.remove(i);
                    continue;
                }
                Some((j, _)) => {
                    tx.remove(j);
                }
                None => {}
            }
        }
        tx.insert(i, new[i].clone());
        i += 1;
    }
    debug_assert_eq!(tx.len(), new.len());
    tx.commit();
}

/// Replaces the whole content; subscribers get one `Reset`
/// (see [`collapse_reset`]).
pub(crate) fn reset<T: Clone + 'static>(vector: &mut ObservableVector<T>, values: Vector<T>) {
    let mut tx = vector.transaction();
    tx.clear();
    tx.append(values);
    tx.commit();
}

/// eyeball-im batches a transaction's `clear` + `append` as two diffs; hand
/// them out as the `Reset` they mean.
pub(crate) fn collapse_reset<T: Clone>(mut diffs: Vec<VectorDiff<T>>) -> Vec<VectorDiff<T>> {
    if let [VectorDiff::Clear, VectorDiff::Append { .. }] = diffs.as_slice() {
        if let Some(VectorDiff::Append { values }) = diffs.pop() {
            return vec![VectorDiff::Reset { values }];
        }
    }
    diffs
}

#[cfg(test)]
mod tests {
    use super::*;

    type Item = (char, u32);

    fn run(old: &[Item], new: &[Item]) -> Vec<VectorDiff<Item>> {
        let mut vector = ObservableVector::from(old.iter().copied().collect::<Vector<_>>());
        let mut sub = vector.subscribe().into_batched_stream();
        update(&mut vector, new, |item| item.0);
        assert_eq!(vector.iter().copied().collect::<Vec<_>>(), new);
        let waker = futures_util::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        match std::pin::Pin::new(&mut sub).poll_next(&mut cx) {
            std::task::Poll::Ready(Some(diffs)) => diffs,
            _ => vec![],
        }
    }

    use futures_core::Stream;

    #[test]
    fn set_in_place() {
        let diffs = run(&[('a', 0), ('b', 0)], &[('a', 0), ('b', 1)]);
        assert_eq!(
            diffs,
            vec![VectorDiff::Set {
                index: 1,
                value: ('b', 1)
            }]
        );
    }

    #[test]
    fn move_up_and_down_is_remove_insert() {
        let old = [('a', 0), ('b', 0), ('c', 0), ('d', 0)];
        let diffs = run(&old, &[('d', 1), ('a', 0), ('b', 0), ('c', 0)]);
        assert_eq!(
            diffs,
            vec![
                VectorDiff::Remove { index: 3 },
                VectorDiff::Insert {
                    index: 0,
                    value: ('d', 1)
                },
            ]
        );
        let diffs = run(&old, &[('b', 0), ('c', 0), ('a', 0), ('d', 0)]);
        assert_eq!(
            diffs,
            vec![
                VectorDiff::Remove { index: 0 },
                VectorDiff::Insert {
                    index: 2,
                    value: ('a', 0)
                },
            ]
        );
    }

    #[test]
    fn swap_moves_the_later_item_up() {
        let diffs = run(&[('a', 0), ('b', 0)], &[('b', 1), ('a', 0)]);
        assert_eq!(
            diffs,
            vec![
                VectorDiff::Remove { index: 1 },
                VectorDiff::Insert {
                    index: 0,
                    value: ('b', 1)
                },
            ]
        );
    }

    #[test]
    fn inserts_and_removes() {
        let diffs = run(
            &[('a', 0), ('c', 0), ('d', 0)],
            &[('x', 0), ('a', 0), ('b', 0)],
        );
        assert_eq!(
            diffs,
            vec![
                VectorDiff::Remove { index: 2 },
                VectorDiff::Remove { index: 1 },
                VectorDiff::Insert {
                    index: 0,
                    value: ('x', 0)
                },
                VectorDiff::Insert {
                    index: 2,
                    value: ('b', 0)
                },
            ]
        );
        assert_eq!(run(&[('a', 0)], &[('a', 0)]), vec![]);
    }

    #[test]
    fn reset_collapses() {
        let mut vector = ObservableVector::from(Vector::from(vec![1]));
        let mut sub = vector.subscribe().into_batched_stream();
        reset(&mut vector, Vector::from(vec![2, 3]));
        let waker = futures_util::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let std::task::Poll::Ready(Some(diffs)) = std::pin::Pin::new(&mut sub).poll_next(&mut cx)
        else {
            panic!("no diffs");
        };
        assert_eq!(
            collapse_reset(diffs),
            vec![VectorDiff::Reset {
                values: Vector::from(vec![2, 3])
            }]
        );
    }
}
