mod common;

use std::pin::pin;
use std::time::Duration;

use common::{next, Device};
use futures_util::StreamExt;
use gim_proto::envelope::Content;
use gim_sdk::testing::FakeTransport;
use gim_ui::{TypingNotifications, TYPING_TIMEOUT};
use tokio::time::Instant;

#[tokio::test(start_paused = true)]
async fn typing_expires_and_ignores_own_devices() {
    let transport = FakeTransport::new();
    let alice = Device::register(&transport, "alice", "Alice").await;
    let bob = Device::register(&transport, "bob", "Bob").await;
    let bob_tablet = Device::register(&transport, "bob", "Bob").await;
    let g = alice
        .client
        .create_group_chat(None, &[bob.user_id()])
        .await
        .unwrap();
    bob.sync().await;
    bob_tablet.sync().await;

    let typing = TypingNotifications::new(&bob.client, g.clone()).unwrap();
    let (initial, stream) = typing.subscribe();
    let mut stream = pin!(stream);
    assert!(initial.is_empty());

    // Bob typing on his other device is not shown.
    bob_tablet.send(&g, Content::Typing { active: true }).await;
    alice.send(&g, Content::Typing { active: true }).await;
    bob.sync().await;
    assert_eq!(next(&mut stream).await, vec![alice.user_id()]);
    let since = Instant::now();

    // Still typing just before the timeout, gone right after it.
    let early = TYPING_TIMEOUT - Duration::from_millis(100);
    assert!(tokio::time::timeout(early, stream.next()).await.is_err());
    assert_eq!(next(&mut stream).await, vec![]);
    assert!(since.elapsed() >= TYPING_TIMEOUT);

    // An explicit stop ends it right away.
    alice.send(&g, Content::Typing { active: true }).await;
    bob.sync().await;
    assert_eq!(next(&mut stream).await, vec![alice.user_id()]);
    alice.send(&g, Content::Typing { active: false }).await;
    bob.sync().await;
    let since = Instant::now();
    assert_eq!(next(&mut stream).await, vec![]);
    assert!(since.elapsed() < TYPING_TIMEOUT);
}
