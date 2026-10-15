//! Media upload and download between clients of the fake server.

mod common;

use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;

use gim_base::model::{MessageContent, SendState};
use gim_base::StateReader;
use gim_common::{GroupId, MessageId};
use gim_proto::envelope::MediaInfo;
use gim_sdk::ClientError;

use common::{Device, FlakyTransport};

const MIB: usize = 1024 * 1024;

/// A 1 MiB file that starts with a 640x480 PNG header.
fn write_image(path: &Path) -> Vec<u8> {
    let mut data = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    data.extend_from_slice(&640u32.to_be_bytes());
    data.extend_from_slice(&480u32.to_be_bytes());
    let mut state = 0x2545_f491_u32;
    while data.len() < MIB {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        data.push(state as u8);
    }
    fs::write(path, &data).unwrap();
    data
}

fn media(device: &Device, id: &MessageId) -> MediaInfo {
    match device.message(id).content {
        MessageContent::Media { media, .. } => media,
        other => panic!("not media: {other:?}"),
    }
}

fn leftovers(device: &Device) -> Vec<String> {
    match fs::read_dir(device.data_dir.path().join("tmp")) {
        Ok(dir) => dir
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect(),
        Err(_) => vec![],
    }
}

async fn chat_with_image(transport: &FlakyTransport) -> (Device, Device, GroupId, MessageId, Vec<u8>) {
    let alice = Device::register(transport, "alice").await;
    let bob = Device::register(transport, "bob").await;
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    let source = alice.data_dir.path().join("photo.png");
    let data = write_image(&source);
    let id = alice
        .client
        .send_media(&g, &source, "image/png", Some("sea".into()), None)
        .await
        .unwrap();
    bob.sync().await;
    (alice, bob, g, id, data)
}

#[tokio::test]
async fn media_round_trip_between_two_clients() {
    let transport = FlakyTransport::new();
    let (alice, bob, g, id, data) = chat_with_image(&transport).await;

    assert_eq!(alice.message(&id).send_state, Some(SendState::Sent));
    let sent = media(&alice, &id);
    assert_eq!(sent.size, MIB as u64);
    assert_eq!((sent.width, sent.height), (Some(640), Some(480)));
    assert_eq!(sent.file_name.as_deref(), Some("photo.png"));
    assert!(leftovers(&alice).is_empty());
    let blob = transport
        .inner
        .service()
        .download_blob(&sent.blob_id, None)
        .unwrap();
    assert_ne!(&blob[16..1040], &data[..1024], "blob is encrypted");

    let received = bob.message(&id);
    assert!(matches!(
        &received.content,
        MessageContent::Media { caption: Some(c), .. } if c == "sea"
    ));
    assert_eq!(media(&bob, &id), sent);

    let dest = bob.data_dir.path().join("downloaded.png");
    bob.client.fetch_media(&g, &id, &dest).await.unwrap();
    assert_eq!(fs::read(&dest).unwrap(), data);
    let cached = bob.store.media(&sent.blob_id).unwrap().unwrap();
    assert_eq!(cached.local_path, dest.to_str().unwrap());
    assert_eq!(cached.size, MIB as u64);
    assert!(leftovers(&bob).is_empty());
    assert_eq!(
        transport.faults.downloaded_bytes.load(Ordering::SeqCst),
        blob.len() as u64
    );

    // A second fetch is served from the cache.
    let copy = bob.data_dir.path().join("copy.png");
    bob.client.fetch_media(&g, &id, &copy).await.unwrap();
    assert_eq!(fs::read(&copy).unwrap(), data);
    assert_eq!(
        transport.faults.downloaded_bytes.load(Ordering::SeqCst),
        blob.len() as u64
    );

    assert!(matches!(
        bob.client
            .fetch_thumbnail(&g, &id, bob.data_dir.path().join("thumb"))
            .await,
        Err(ClientError::InvalidInput(_))
    ));
}

#[tokio::test]
async fn tampered_blob_is_rejected() {
    let transport = FlakyTransport::new();
    let (_alice, bob, g, id, _) = chat_with_image(&transport).await;

    transport.faults.tamper.store(true, Ordering::SeqCst);
    let dest = bob.data_dir.path().join("downloaded.png");
    let fetched = bob.client.fetch_media(&g, &id, &dest).await;
    assert!(matches!(fetched, Err(ClientError::Media(_))), "{fetched:?}");
    assert!(!dest.exists());
    assert!(leftovers(&bob).is_empty());
    assert!(bob
        .store
        .media(&media(&bob, &id).blob_id)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn interrupted_download_resumes_from_the_partial_file() {
    let transport = FlakyTransport::new();
    let (_alice, bob, g, id, data) = chat_with_image(&transport).await;
    let blob_len = transport
        .inner
        .service()
        .download_blob(&media(&bob, &id).blob_id, None)
        .unwrap()
        .len() as u64;

    // Header plus two pieces, then the network drops.
    *transport.faults.downloads_left.lock().unwrap() = Some(3);
    let dest = bob.data_dir.path().join("downloaded.png");
    assert!(matches!(
        bob.client.fetch_media(&g, &id, &dest).await,
        Err(ClientError::Transport(_))
    ));
    assert!(!dest.exists());
    assert_eq!(leftovers(&bob).len(), 1);

    *transport.faults.downloads_left.lock().unwrap() = None;
    bob.client.fetch_media(&g, &id, &dest).await.unwrap();
    assert_eq!(fs::read(&dest).unwrap(), data);
    // Nothing was downloaded twice.
    assert_eq!(
        transport.faults.downloaded_bytes.load(Ordering::SeqCst),
        blob_len
    );
    assert!(leftovers(&bob).is_empty());
}

#[tokio::test]
async fn unreadable_file_fails_the_message() {
    let transport = FlakyTransport::new();
    let alice = Device::register(&transport, "alice").await;
    let bob = Device::register(&transport, "bob").await;
    let g = alice
        .client
        .create_direct_chat(&bob.user_id())
        .await
        .unwrap();
    let missing = alice.data_dir.path().join("missing.jpg");
    let id = alice
        .client
        .send_media(&g, &missing, "image/jpeg", None, None)
        .await
        .unwrap();
    assert_eq!(alice.message(&id).send_state, Some(SendState::Failed));
    // The chat is not blocked by it.
    let text = alice.client.send_text(&g, "text", None).await.unwrap();
    assert_eq!(alice.message(&text).send_state, Some(SendState::Sent));
}
