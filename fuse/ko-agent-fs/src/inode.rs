//! The inode table of the path inode model (`doc/architecture.md`). FUSE addresses objects by inode
//! number and `(parent, name)`, so this maps those to a position in the backing tree: each entry keeps its
//! parent, basename, kernel lookup count, and cached [`GitContext`]. A path is reconstructed by
//! walking parents to the root only when an operation needs one; nothing here caches attributes or
//! opens backing fds (that is the resolver's job, per operation).
//!
//! `forget` is honored so the table stays bounded to what the kernel currently references — the
//! property that keeps memory flat while a compiler stats hundreds of thousands of files.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

use crate::policy::{GitContext, child_context, gitdir_root};

/// The FUSE root inode number is fixed by the protocol.
pub const ROOT_INO: u64 = 1;

/// One live inode: where it sits in the tree and its cached Git position.
#[derive(Debug)]
pub struct Inode {
    pub parent: u64,
    /// Basename in the parent directory; empty only for the root.
    pub name: OsString,
    /// Outstanding kernel references (sum of `lookup`/`entry` replies minus `forget`s).
    pub nlookup: u64,
    pub git: GitContext,
}

/// Maps inode numbers to positions, reusing a number for a `(parent, name)` while it is referenced
/// so the kernel sees a stable inode, and dropping entries once the kernel forgets them.
pub struct InodeTable {
    by_ino: HashMap<u64, Inode>,
    by_name: HashMap<(u64, OsString), u64>,
    next_ino: u64,
}

impl InodeTable {
    pub fn new() -> Self {
        let mut by_ino = HashMap::new();
        by_ino.insert(
            ROOT_INO,
            Inode {
                parent: ROOT_INO,
                name: OsString::new(),
                nlookup: 1,
                git: GitContext::root(),
            },
        );
        InodeTable {
            by_ino,
            by_name: HashMap::new(),
            next_ino: ROOT_INO + 1,
        }
    }

    pub fn get(&self, ino: u64) -> Option<&Inode> {
        self.by_ino.get(&ino)
    }

    /// The path components (basenames) from `ino` up to — but not including — the root, or `None`
    /// if the inode (or an ancestor) is unknown. The empty vector is the root itself.
    pub fn components(&self, ino: u64) -> Option<Vec<Vec<u8>>> {
        let mut parts = Vec::new();
        let mut current = ino;
        while current != ROOT_INO {
            let node = self.by_ino.get(&current)?;
            parts.push(node.name.as_bytes().to_vec());
            current = node.parent;
        }
        parts.reverse();
        Some(parts)
    }

    /// Record a successful `lookup(parent, name)`: reuse or allocate an inode number, bump its
    /// kernel reference count, and return it. The Git context is computed once, here, from the
    /// parent's — the O(1) step that every later operation on this inode reads instead of recomputing.
    ///
    /// `is_gitdir_root` ([`GitContext::ModuleNamespace`]) only matters where the context would
    /// otherwise be a namespace. It is read on the
    /// allocating path alone: a reused entry keeps the context it was created with, so a directory
    /// that *becomes* a gitdir root after its first lookup stays a namespace — control — until the
    /// kernel forgets it. Both drift directions land on the stricter answer.
    pub fn lookup(&mut self, parent: u64, name: &OsStr, is_gitdir_root: bool) -> u64 {
        let key = (parent, name.to_os_string());
        if let Some(&ino) = self.by_name.get(&key) {
            if let Some(node) = self.by_ino.get_mut(&ino) {
                node.nlookup += 1;
            }
            return ino;
        }

        let parent_git = self
            .by_ino
            .get(&parent)
            .map_or(GitContext::NotGit, |node| node.git.clone());
        let git = match child_context(&parent_git, name.as_bytes()) {
            GitContext::ModuleNamespace if is_gitdir_root => gitdir_root(),
            other => other,
        };

        let ino = self.next_ino;
        self.next_ino += 1;
        self.by_ino.insert(
            ino,
            Inode {
                parent,
                name: name.to_os_string(),
                nlookup: 1,
                git,
            },
        );
        self.by_name.insert(key, ino);
        ino
    }

    /// Apply a kernel `forget(ino, n)`: drop `n` references and, at zero, remove the entry. The root
    /// is never removed.
    pub fn forget(&mut self, ino: u64, n: u64) {
        if ino == ROOT_INO {
            return;
        }
        if let Some(node) = self.by_ino.get_mut(&ino) {
            node.nlookup = node.nlookup.saturating_sub(n);
            if node.nlookup == 0 {
                let key = (node.parent, node.name.clone());
                self.by_ino.remove(&ino);
                self.by_name.remove(&key);
            }
        }
    }

    /// The `(parent, basename)` of `ino`, or `None` for the root (which has neither) or an unknown
    /// inode. Used where an operation needs the parent directory and the final name — e.g. reading a
    /// symlink through its parent fd.
    pub fn parent_and_name(&self, ino: u64) -> Option<(u64, OsString)> {
        if ino == ROOT_INO {
            return None;
        }
        self.by_ino
            .get(&ino)
            .map(|node| (node.parent, node.name.clone()))
    }

    /// Live entries, for tests and diagnostics.
    pub fn len(&self) -> usize {
        self.by_ino.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ino.is_empty()
    }
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{GitPathClass, classify};

    fn os(s: &str) -> &OsStr {
        OsStr::new(s)
    }

    /// An ordinary lookup: nothing outside a `modules/` namespace is ever a gitdir root, so the
    /// hint is `false` everywhere but the one test that exercises it.
    fn look(table: &mut InodeTable, parent: u64, name: &str) -> u64 {
        table.lookup(parent, os(name), false)
    }

    #[test]
    fn root_exists_and_has_no_components() {
        let table = InodeTable::new();
        assert_eq!(table.components(ROOT_INO), Some(vec![]));
        assert!(matches!(
            table.get(ROOT_INO).map(|n| &n.git),
            Some(GitContext::NotGit)
        ));
    }

    #[test]
    fn lookup_allocates_then_reuses_the_same_inode() {
        let mut table = InodeTable::new();
        let a = look(&mut table, ROOT_INO, "src");
        let b = look(&mut table, ROOT_INO, "src");
        assert_eq!(a, b, "same (parent,name) must reuse the inode");
        assert_eq!(table.get(a).unwrap().nlookup, 2);
        let other = look(&mut table, ROOT_INO, "docs");
        assert_ne!(a, other);
    }

    #[test]
    fn components_reconstruct_a_nested_path() {
        let mut table = InodeTable::new();
        let src = look(&mut table, ROOT_INO, "src");
        let main = look(&mut table, src, "main.rs");
        assert_eq!(
            table.components(main),
            Some(vec![b"src".to_vec(), b"main.rs".to_vec()])
        );
    }

    #[test]
    fn forget_is_reference_counted_and_bounds_the_table() {
        let mut table = InodeTable::new();
        let ino = look(&mut table, ROOT_INO, "a");
        look(&mut table, ROOT_INO, "a"); // nlookup = 2
        assert_eq!(table.len(), 2); // root + a

        table.forget(ino, 1);
        assert!(table.get(ino).is_some(), "still referenced");
        table.forget(ino, 1);
        assert!(table.get(ino).is_none(), "dropped at zero references");
        assert_eq!(table.len(), 1); // just the root

        // The name is free to be allocated a fresh inode afterwards.
        let reallocated = look(&mut table, ROOT_INO, "a");
        assert_ne!(reallocated, ino);
    }

    #[test]
    fn forget_never_removes_the_root() {
        let mut table = InodeTable::new();
        table.forget(ROOT_INO, 100);
        assert!(table.get(ROOT_INO).is_some());
    }

    #[test]
    fn git_context_is_computed_and_cached_down_a_gitdir() {
        let mut table = InodeTable::new();
        let dotgit = look(&mut table, ROOT_INO, ".git");
        assert_eq!(
            classify(&table.get(dotgit).unwrap().git),
            GitPathClass::Control
        );

        let hooks = look(&mut table, dotgit, "hooks");
        let hook = look(&mut table, hooks, "pre-commit");
        assert_eq!(
            classify(&table.get(hook).unwrap().git),
            GitPathClass::Control
        );

        let refs = look(&mut table, dotgit, "refs");
        let head = look(&mut table, refs, "heads");
        let main = look(&mut table, head, "main");
        assert_eq!(
            classify(&table.get(main).unwrap().git),
            GitPathClass::Operational
        );
    }

    #[test]
    fn a_nested_submodule_gitdir_keeps_its_objects_writable() {
        // The hint is what the plumbing answers for a directory under `modules/` that holds a
        // `HEAD` (`fs.rs`, `is_gitdir_root`); `libs/foo` is the ordinary two-component name a
        // submodule in a subdirectory gets, and it must behave as any other gitdir does.
        let mut table = InodeTable::new();
        let dotgit = look(&mut table, ROOT_INO, ".git");
        let modules = look(&mut table, dotgit, "modules");
        let libs = look(&mut table, modules, "libs");
        let foo = table.lookup(libs, os("foo"), true);

        let objects = look(&mut table, foo, "objects");
        let pack = look(&mut table, objects, "pack");
        assert_eq!(
            classify(&table.get(pack).unwrap().git),
            GitPathClass::Operational
        );
        // But the submodule's own hooks are still control, and so is the namespace above it.
        let hooks = look(&mut table, foo, "hooks");
        assert_eq!(
            classify(&table.get(hooks).unwrap().git),
            GitPathClass::Control
        );
        assert_eq!(
            classify(&table.get(libs).unwrap().git),
            GitPathClass::Control
        );
    }

    #[test]
    fn a_directory_under_modules_without_the_hint_stays_frozen() {
        // The fail-closed half: with no `HEAD` to find, the plumbing answers `false` and everything
        // below reads as namespace. A tree the daemon cannot identify is never widened.
        let mut table = InodeTable::new();
        let dotgit = look(&mut table, ROOT_INO, ".git");
        let modules = look(&mut table, dotgit, "modules");
        let libs = look(&mut table, modules, "libs");
        let foo = look(&mut table, libs, "foo");
        let objects = look(&mut table, foo, "objects");
        assert_eq!(
            classify(&table.get(objects).unwrap().git),
            GitPathClass::Control
        );
    }
}
