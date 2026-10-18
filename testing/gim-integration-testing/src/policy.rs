//! The user policy of a real gim-hub container (hub `operations.md`, "User
//! policy"), set with its `gim-hub config` CLI over `docker exec`. The hub
//! applies CLI changes within about a second.

use std::time::Duration;

use crate::federation::docker_exec;

/// How long a CLI change takes at most to apply on the hub.
pub const POLICY_APPLY: Duration = Duration::from_secs(3);

/// The container of the single hub under test (`GIM_HUB_CONTAINER`, set by
/// `scripts/integration-test.sh` with the Docker socket mounted), or `None`
/// (after printing a notice) when unset.
pub fn hub_container(test: &str) -> Option<String> {
    match std::env::var("GIM_HUB_CONTAINER") {
        Ok(name) if !name.is_empty() => Some(name),
        _ => {
            eprintln!("skipping {test}: GIM_HUB_CONTAINER is not set");
            None
        }
    }
}

/// `gim-hub config ARGS` in `container`; panics unless it exits 0.
fn config(container: &str, args: &[&str]) {
    let cmd: Vec<&str> = ["gim-hub", "config"].iter().chain(args).copied().collect();
    let (code, output) = docker_exec(container, &cmd).unwrap();
    assert_eq!(code, 0, "{cmd:?} in {container}: {output}");
}

/// A hub in `deny` mode listing some users. Dropping it restores the
/// `open` policy and unlists them, so the other tests on that hub are not
/// affected.
pub struct DenyList {
    container: String,
    users: Vec<String>,
}

impl DenyList {
    /// Lists `users` on the hub in `container`, then switches it to `deny`.
    /// Call [`DenyList::applied`] before relying on it.
    pub fn new(container: &str, users: &[&str]) -> Self {
        let mut list = Self {
            container: container.to_string(),
            users: Vec::new(),
        };
        for user in users {
            config(container, &["users", "add", user]);
            list.users.push(user.to_string());
        }
        config(container, &["set", "GIM_HUB_USER_POLICY", "deny"]);
        list
    }

    /// Waits until the hub applied the change.
    pub async fn applied(&self) {
        tokio::time::sleep(POLICY_APPLY).await;
    }
}

impl Drop for DenyList {
    fn drop(&mut self) {
        // Best effort and without panicking: also while a failed test
        // unwinds.
        let _ = docker_exec(
            &self.container,
            &["gim-hub", "config", "set", "GIM_HUB_USER_POLICY", "open"],
        );
        for user in &self.users {
            let _ = docker_exec(
                &self.container,
                &["gim-hub", "config", "users", "remove", user],
            );
        }
    }
}
