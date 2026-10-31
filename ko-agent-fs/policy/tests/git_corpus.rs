//! The static corpus of what real git writes (`corpus::OPERATIONAL` and its neighbours), through
//! `policy.rs`.

mod corpus;

use ko_agent_fs::policy::{GitPathClass, classify_relative_path};

#[track_caller]
fn operational(path: &str) {
    assert_eq!(
        classify_relative_path(path.as_bytes(), corpus::GITDIR_ROOTS),
        GitPathClass::Operational,
        "expected {path} to be writable"
    );
}

#[track_caller]
fn protected(path: &str) {
    assert_eq!(
        classify_relative_path(path.as_bytes(), corpus::GITDIR_ROOTS),
        GitPathClass::Protected,
        "expected {path} to be frozen"
    );
}

#[test]
fn operational_state_git_writes_during_normal_ops_stays_writable() {
    for path in corpus::OPERATIONAL {
        operational(path);
    }
}

#[test]
fn state_observe_git_misses_stays_writable() {
    for path in corpus::OPERATIONAL_UNOBSERVED {
        operational(path);
    }
}

#[test]
fn protected_entries_stay_frozen() {
    for path in corpus::PROTECTED {
        protected(path);
    }
}

#[test]
fn rebase_and_sequencer_todo_state_is_frozen() {
    for path in corpus::PROTECTED_TODO_STATE {
        protected(path);
    }
}

#[test]
fn the_dotgit_entry_itself_is_frozen_however_it_is_named() {
    for path in corpus::DOTGIT_ENTRIES {
        protected(path);
    }
}
