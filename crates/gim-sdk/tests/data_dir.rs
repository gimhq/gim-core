//! The data directory is required and its `tmp` subdirectory private.

use std::sync::Arc;

use gim_base::MemoryStore;
use gim_sdk::testing::{FakeTransport, MemorySecretStorage};
use gim_sdk::{Client, ClientBuilder, ClientError, SecretStorage};

fn builder() -> ClientBuilder<MemoryStore> {
    ClientBuilder::new(
        Arc::new(MemoryStore::new()),
        Arc::new(FakeTransport::new()),
        Arc::new(MemorySecretStorage::new()) as Arc<dyn SecretStorage>,
    )
}

fn build_err(builder: ClientBuilder<MemoryStore>) -> ClientError {
    match builder.build() {
        Ok(_) => panic!("built"),
        Err(err) => err,
    }
}

#[test]
fn data_dir_is_required() {
    assert!(matches!(build_err(builder()), ClientError::InvalidInput(_)));
}

#[cfg(unix)]
#[test]
fn build_creates_private_dirs() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let data_dir = root.path().join("a").join("b");
    let _client: Client<MemoryStore> = builder().data_dir(&data_dir).build().unwrap();
    for dir in [data_dir.clone(), data_dir.join("tmp")] {
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "{}", dir.display());
    }
}

#[cfg(unix)]
#[test]
fn insecure_tmp_dir_is_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let elsewhere = root.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();

    let linked = root.path().join("linked");
    std::fs::create_dir(&linked).unwrap();
    std::os::unix::fs::symlink(&elsewhere, linked.join("tmp")).unwrap();
    assert!(matches!(
        build_err(builder().data_dir(&linked)),
        ClientError::InvalidInput(_)
    ));

    let shared = root.path().join("shared");
    std::fs::create_dir_all(shared.join("tmp")).unwrap();
    std::fs::set_permissions(shared.join("tmp"), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        build_err(builder().data_dir(&shared)),
        ClientError::InvalidInput(_)
    ));
}
