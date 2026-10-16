use ciborium::Value;
use gim_common::{GroupId, MessageId, UserId};
use gim_proto::envelope::{
    decode, encode, Contact, Content, Envelope, HubLocation, MediaInfo, ReceiptKind,
    ENVELOPE_VERSION,
};
use gim_proto::ProtoError;

fn mid(id: &str) -> MessageId {
    MessageId::new(id).unwrap()
}

fn media(full: bool) -> MediaInfo {
    MediaInfo {
        blob_id: "blob-1".into(),
        key: [7; 32],
        sha256: [9; 32],
        mime: "image/jpeg".into(),
        size: 123_456,
        width: full.then_some(640),
        height: full.then_some(480),
        file_name: full.then(|| "harbour.jpg".into()),
        thumbnail: full.then(|| vec![1, 2, 3]),
    }
}

fn all_contents() -> Vec<Content> {
    vec![
        Content::Text {
            body: "Kalimera from Hydra".into(),
        },
        Content::Text {
            body: String::new(),
        },
        Content::Media {
            media: media(true),
            caption: Some("Anchored".into()),
        },
        Content::Media {
            media: media(false),
            caption: None,
        },
        Content::Edit {
            target: mid("m1"),
            new_body: "edited".into(),
        },
        Content::Delete { target: mid("m1") },
        Content::Reaction {
            target: mid("m1"),
            emoji: "⛵".into(),
            remove: false,
        },
        Content::Reaction {
            target: mid("m1"),
            emoji: "⛵".into(),
            remove: true,
        },
        Content::Receipt {
            kind: ReceiptKind::Delivered,
            message_ids: vec![mid("m1"), mid("m2")],
        },
        Content::Receipt {
            kind: ReceiptKind::Read,
            message_ids: vec![],
        },
        Content::Typing { active: true },
        Content::Typing { active: false },
        Content::GroupInfo {
            name: Some("Aegean crew".into()),
            avatar: Some(media(true)),
        },
        Content::GroupInfo {
            name: None,
            avatar: None,
        },
        Content::Profile {
            display_name: "Eleni".into(),
        },
        Content::SelfDeviceList {
            device_list: vec![0x82, 0x40, 0x40],
        },
        Content::SelfProfile {
            display_name: "Eleni on Hydra".into(),
        },
        Content::SelfContacts {
            contacts: vec![
                Contact {
                    user_id: UserId::new("ubob").unwrap(),
                    handle: Some("bob".into()),
                    display_name: Some("Bob".into()),
                },
                Contact {
                    user_id: UserId::new("ucarol").unwrap(),
                    handle: None,
                    display_name: None,
                },
            ],
        },
        Content::SelfContacts { contacts: vec![] },
        Content::SelfReadMarker {
            group_id: GroupId::new("hub/abc").unwrap(),
            seq: 42,
        },
        Content::SelfHubs {
            hubs: vec![
                HubLocation {
                    hub_id: "hpiraeus".into(),
                    url: "https://hub.piraeus.example".into(),
                    priority: 0,
                },
                HubLocation {
                    hub_id: "hsplit".into(),
                    url: "https://hub.split.example:8443/gim".into(),
                    priority: 255,
                },
            ],
        },
        Content::SelfHubs { hubs: vec![] },
    ]
}

fn envelope(content: Content) -> Envelope {
    Envelope::new(mid("msg-1"), 1_760_000_000_000, content)
}

fn to_value(bytes: &[u8]) -> Value {
    ciborium::from_reader(bytes).unwrap()
}

fn to_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

fn map_mut(value: &mut Value) -> &mut Vec<(Value, Value)> {
    match value {
        Value::Map(map) => map,
        _ => panic!("not a map"),
    }
}

fn entry_mut<'a>(map: &'a mut [(Value, Value)], key: &str) -> &'a mut Value {
    &mut map
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(key))
        .unwrap()
        .1
}

#[test]
fn round_trips_every_variant() {
    for content in all_contents() {
        let env = envelope(content);
        assert_eq!(decode(&encode(&env).unwrap()).unwrap(), env);
    }
}

#[test]
fn round_trips_reply_to_on_text_and_media() {
    for content in all_contents() {
        if !matches!(content, Content::Text { .. } | Content::Media { .. }) {
            continue;
        }
        let mut env = envelope(content);
        env.reply_to = Some(mid("parent"));
        assert_eq!(decode(&encode(&env).unwrap()).unwrap(), env);
    }
}

#[test]
fn rejects_reply_to_on_other_variants() {
    for content in all_contents() {
        if matches!(content, Content::Text { .. } | Content::Media { .. }) {
            continue;
        }
        let mut env = envelope(content);
        env.reply_to = Some(mid("parent"));
        assert!(matches!(encode(&env), Err(ProtoError::InvalidInput { .. })));

        // Also on decode, when another encoder produced it.
        env.reply_to = None;
        let mut value = to_value(&encode(&env).unwrap());
        map_mut(&mut value).push((Value::Text("re".into()), Value::Text("parent".into())));
        assert!(matches!(
            decode(&to_bytes(&value)),
            Err(ProtoError::InvalidInput { .. })
        ));
    }
}

#[test]
fn uses_short_keys() {
    let value = to_value(&encode(&envelope(Content::Typing { active: true })).unwrap());
    let keys: Vec<_> = value
        .as_map()
        .unwrap()
        .iter()
        .map(|(k, _)| k.as_text().unwrap().to_owned())
        .collect();
    assert_eq!(keys, ["v", "id", "ts", "c"]);
}

#[test]
fn rejects_unsupported_versions() {
    for version in [0, ENVELOPE_VERSION + 1] {
        let mut env = envelope(Content::Typing { active: true });
        env.version = version;
        assert_eq!(
            encode(&env),
            Err(ProtoError::UnsupportedVersion {
                version: version.into()
            })
        );

        let mut value = to_value(&encode(&envelope(Content::Typing { active: true })).unwrap());
        *entry_mut(map_mut(&mut value), "v") = Value::Integer(version.into());
        assert_eq!(
            decode(&to_bytes(&value)),
            Err(ProtoError::UnsupportedVersion {
                version: version.into()
            })
        );
    }
}

#[test]
fn rejects_garbage() {
    for bytes in [
        &b""[..],
        b"\xff",
        b"\x00",
        b"not cbor at all",
        &to_bytes(&Value::Array(vec![])),
        &to_bytes(&Value::Map(vec![])),
    ] {
        assert!(matches!(decode(bytes), Err(ProtoError::Malformed { .. })));
    }
    let valid = encode(&envelope(Content::Text { body: "x".into() })).unwrap();
    for len in 0..valid.len() {
        assert!(decode(&valid[..len]).is_err());
    }
}

#[test]
fn rejects_unknown_variant() {
    let mut value = to_value(&encode(&envelope(Content::Typing { active: true })).unwrap());
    let content = entry_mut(map_mut(&mut value), "c");
    *entry_mut(map_mut(content), "t") = Value::Text("sticker".into());
    assert!(matches!(
        decode(&to_bytes(&value)),
        Err(ProtoError::Malformed { .. })
    ));
}

#[test]
fn ignores_unknown_keys() {
    let env = envelope(Content::Media {
        media: media(true),
        caption: None,
    });
    let mut value = to_value(&encode(&env).unwrap());
    let top = map_mut(&mut value);
    top.push((Value::Text("zz".into()), Value::Bool(true)));
    let content = map_mut(entry_mut(top, "c"));
    content.push((Value::Text("zz".into()), Value::Integer(1.into())));
    map_mut(entry_mut(content, "m")).push((Value::Text("zz".into()), Value::Null));
    assert_eq!(decode(&to_bytes(&value)).unwrap(), env);
}

#[test]
fn rejects_wrong_media_key_length() {
    let env = envelope(Content::Media {
        media: media(false),
        caption: None,
    });
    for field in ["k", "d"] {
        let mut value = to_value(&encode(&env).unwrap());
        let content = map_mut(entry_mut(map_mut(&mut value), "c"));
        *entry_mut(map_mut(entry_mut(content, "m")), field) = Value::Bytes(vec![0; 31]);
        assert!(matches!(
            decode(&to_bytes(&value)),
            Err(ProtoError::InvalidInput { .. })
        ));
    }
}

#[test]
fn rejects_invalid_message_id() {
    let mut value = to_value(&encode(&envelope(Content::Typing { active: true })).unwrap());
    *entry_mut(map_mut(&mut value), "id") = Value::Text("a/b".into());
    assert!(matches!(
        decode(&to_bytes(&value)),
        Err(ProtoError::Malformed { .. })
    ));
}

fn content_map(env: &Envelope) -> Vec<(String, Value)> {
    let value = to_value(&encode(env).unwrap());
    let content = value
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_text() == Some("c"))
        .unwrap()
        .1
        .clone();
    content
        .as_map()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.as_text().unwrap().to_owned(), v.clone()))
        .collect()
}

#[test]
fn profile_and_self_group_tags() {
    let tag = |content: Content| {
        content_map(&envelope(content))
            .into_iter()
            .find(|(k, _)| k == "t")
            .and_then(|(_, v)| v.as_text().map(str::to_owned))
            .unwrap()
    };
    assert_eq!(
        tag(Content::Profile {
            display_name: "x".into()
        }),
        "profile"
    );
    assert_eq!(
        tag(Content::SelfDeviceList {
            device_list: vec![1]
        }),
        "self.device_list"
    );
    assert_eq!(
        tag(Content::SelfProfile {
            display_name: "x".into()
        }),
        "self.profile"
    );
    assert_eq!(
        tag(Content::SelfContacts { contacts: vec![] }),
        "self.contacts"
    );
    assert_eq!(
        tag(Content::SelfReadMarker {
            group_id: GroupId::new("hub/abc").unwrap(),
            seq: 1
        }),
        "self.read_marker"
    );
    assert_eq!(tag(Content::SelfHubs { hubs: vec![] }), "self.hubs");
    let hubs = content_map(&envelope(Content::SelfHubs {
        hubs: vec![HubLocation {
            hub_id: "hpiraeus".into(),
            url: "https://hub.piraeus.example".into(),
            priority: 1,
        }],
    }));
    assert_eq!(
        hubs[1],
        (
            "h".to_owned(),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("id".into()), Value::Text("hpiraeus".into())),
                (
                    Value::Text("u".into()),
                    Value::Text("https://hub.piraeus.example".into())
                ),
                (Value::Text("p".into()), Value::Integer(1.into())),
            ])])
        )
    );

    let marker = content_map(&envelope(Content::SelfReadMarker {
        group_id: GroupId::new("hub/abc").unwrap(),
        seq: 7,
    }));
    let keys: Vec<&str> = marker.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, ["t", "g", "s"]);
    let list = content_map(&envelope(Content::SelfDeviceList {
        device_list: vec![1, 2],
    }));
    assert_eq!(list[1], ("dl".to_owned(), Value::Bytes(vec![1, 2])));

    // A contact without optional fields is just its id.
    let contacts = content_map(&envelope(Content::SelfContacts {
        contacts: vec![Contact {
            user_id: UserId::new("ubob").unwrap(),
            handle: None,
            display_name: None,
        }],
    }));
    assert_eq!(
        contacts[1].1,
        Value::Array(vec![Value::Map(vec![(
            Value::Text("id".into()),
            Value::Text("ubob".into())
        )])])
    );
}

#[test]
fn rejects_invalid_read_marker_group() {
    let env = envelope(Content::SelfReadMarker {
        group_id: GroupId::new("hub/abc").unwrap(),
        seq: 1,
    });
    let mut value = to_value(&encode(&env).unwrap());
    let content = map_mut(entry_mut(map_mut(&mut value), "c"));
    *entry_mut(content, "g") = Value::Text(String::new());
    assert!(matches!(
        decode(&to_bytes(&value)),
        Err(ProtoError::Malformed { .. })
    ));
}
