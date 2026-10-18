//! A closed federation of real gim-hub containers (see `gim-hub-dev.sh
//! fed-start`, run by `GIM_FEDERATION=1 scripts/integration-test.sh`): hubs
//! a and b (and c with `GIM_FED_HUBS=3`) allow each other; hub x is on
//! nobody's allowlist. Hubs are stopped and started through the Docker
//! Engine API on the mounted Docker socket.

use std::process::Command;
use std::time::Duration;

/// How long federated waits poll: they may span a peer's backoff
/// (`GIM_HUB_OUTBOX_BACKOFF_MAX_SECONDS`) or a hub restart.
pub const FED_TIMEOUT: Duration = Duration::from_secs(90);

const DOCKER_SOCKET: &str = "/var/run/docker.sock";

/// One hub of the federation.
#[derive(Debug, Clone)]
pub struct Hub {
    /// Client API base URL.
    pub url: String,
    pub container: String,
    pub hub_id: String,
}

impl Hub {
    fn from_env(name: &str) -> Option<Self> {
        let var = |key: &str| {
            std::env::var(format!("GIM_FED_{key}_{name}"))
                .ok()
                .filter(|v| !v.is_empty())
        };
        Some(Self {
            url: var("HUB")?,
            container: var("CONTAINER")?,
            hub_id: var("HUB_ID")?,
        })
    }

    /// Starts the container if it is stopped, without waiting.
    pub fn start_container(&self) {
        docker_api(&format!("/containers/{}/start", self.container));
    }

    /// The container's log (stdout and stderr, with the Engine API's
    /// stream headers).
    pub fn logs(&self) -> String {
        let out = Command::new("curl")
            .args([
                "-sf",
                "--unix-socket",
                DOCKER_SOCKET,
                &format!(
                    "http://localhost/containers/{}/logs?stdout=1&stderr=1",
                    self.container
                ),
            ])
            .output()
            .expect("curl runs");
        assert!(out.status.success(), "docker logs {}", self.container);
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Stops the container (its data volume is kept).
    pub fn stop(&self) {
        docker_api(&format!("/containers/{}/stop?t=10", self.container));
    }

    /// Starts the stopped container and waits for its `/healthz`.
    pub async fn start(&self) {
        self.start_container();
        let health = format!("{}/healthz", self.url);
        crate::eventually_within("hub healthy after start", FED_TIMEOUT, || async {
            let ok = Command::new("curl")
                .args(["-sf", "-o", "/dev/null", "--max-time", "2", &health])
                .status()
                .is_ok_and(|s| s.success());
            ok.then_some(())
        })
        .await;
    }
}

/// Runs `cmd` in the running container `container` (`docker exec`
/// through the Engine API): its exit code and output (stdout and stderr,
/// with the Engine API's stream headers), or why the Engine API failed.
pub fn docker_exec(container: &str, cmd: &[&str]) -> Result<(i64, String), String> {
    let curl = |method: &str, path: &str, body: Option<String>| {
        let mut args = vec![
            "-sf".to_string(),
            "--unix-socket".into(),
            DOCKER_SOCKET.into(),
            "-X".into(),
            method.into(),
        ];
        if let Some(body) = body {
            args.extend(["-H".into(), "Content-Type: application/json".into()]);
            args.extend(["-d".into(), body]);
        }
        args.push(format!("http://localhost{path}"));
        match Command::new("curl").args(&args).output() {
            Ok(out) if out.status.success() => Ok(out.stdout),
            _ => Err(format!("docker API {method} {path} failed")),
        }
    };
    let json = |bytes: Vec<u8>| {
        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e| e.to_string())
    };
    let create = serde_json::json!({"AttachStdout": true, "AttachStderr": true, "Cmd": cmd});
    let created = json(curl(
        "POST",
        &format!("/containers/{container}/exec"),
        Some(create.to_string()),
    )?)?;
    let id = created["Id"].as_str().ok_or("no exec id")?.to_string();
    let output = curl(
        "POST",
        &format!("/exec/{id}/start"),
        Some(r#"{"Detach":false,"Tty":false}"#.into()),
    )?;
    let inspected = json(curl("GET", &format!("/exec/{id}/json"), None)?)?;
    let code = inspected["ExitCode"].as_i64().unwrap_or(-1);
    Ok((code, String::from_utf8_lossy(&output).into_owned()))
}

/// POSTs to the Docker Engine API; 204 (done) and 304 (already in that
/// state) succeed.
fn docker_api(path: &str) {
    let out = Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--unix-socket",
            DOCKER_SOCKET,
            "-X",
            "POST",
            &format!("http://localhost{path}"),
        ])
        .output()
        .expect("curl runs");
    let code = String::from_utf8_lossy(&out.stdout);
    assert!(
        matches!(code.as_ref(), "204" | "304"),
        "docker API POST {path}: {code} {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The federation under test.
#[derive(Debug, Clone)]
pub struct Federation {
    pub a: Hub,
    pub b: Hub,
    /// Only with `GIM_FED_HUBS=3`.
    pub c: Option<Hub>,
    /// Allowed by none of the others.
    pub x: Hub,
}

impl Federation {
    /// The federation, or `None` (after printing a notice) when
    /// `GIM_FED_HUB_A` is unset and the test should pass without running.
    pub fn from_env(test: &str) -> Option<Self> {
        let Some(a) = Hub::from_env("A") else {
            eprintln!("skipping {test}: GIM_FED_HUB_A is not set");
            return None;
        };
        Some(Self {
            a,
            b: Hub::from_env("B").expect("GIM_FED_*_B"),
            c: Hub::from_env("C"),
            x: Hub::from_env("X").expect("GIM_FED_*_X"),
        })
    }
}
