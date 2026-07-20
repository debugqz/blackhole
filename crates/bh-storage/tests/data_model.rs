use bh_storage::models::{
    Contact, ConversationKind, Device, DeviceOwner, DownloadState, FileMeta, Group, Message,
    MessageRequestStatus, OwnIdentity, Session,
};
use bh_storage::Database;

fn test_key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn open_test_db() -> Database {
    Database::open_in_memory(&test_key(0x42)).expect("open in-memory db")
}

#[test]
fn own_identity_roundtrip() {
    let db = open_test_db();
    assert!(db.get_own_identity().unwrap().is_none());

    let identity = OwnIdentity {
        identity_public_key: vec![1, 2, 3],
        identity_private_key: vec![4, 5, 6],
        created_at: 1000,
    };
    db.set_own_identity(&identity).unwrap();

    let loaded = db.get_own_identity().unwrap().unwrap();
    assert_eq!(loaded.identity_public_key, vec![1, 2, 3]);
    assert_eq!(loaded.identity_private_key, vec![4, 5, 6]);
}

#[test]
fn contacts_crud_and_flags() {
    let db = open_test_db();
    let contact = Contact {
        contact_id: "c1".into(),
        identity_public_key: vec![9, 9, 9],
        display_name: Some("Alice".into()),
        verified: false,
        blocked: false,
        added_at: 100,
    };
    db.upsert_contact(&contact).unwrap();

    assert_eq!(db.list_contacts().unwrap().len(), 1);
    assert_eq!(
        db.get_contact("c1").unwrap().unwrap().display_name,
        Some("Alice".into())
    );

    db.set_contact_blocked("c1", true).unwrap();
    assert!(db.get_contact("c1").unwrap().unwrap().blocked);

    db.set_contact_verified("c1", true).unwrap();
    assert!(db.get_contact("c1").unwrap().unwrap().verified);

    assert!(db.get_contact("nonexistent").unwrap().is_none());
}

#[test]
fn message_requests_default_to_pending() {
    let db = open_test_db();
    db.upsert_contact(&Contact {
        contact_id: "c1".into(),
        identity_public_key: vec![1],
        display_name: None,
        verified: false,
        blocked: false,
        added_at: 0,
    })
    .unwrap();

    db.create_message_request("c1", 200).unwrap();
    let pending = db.list_pending_message_requests().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, MessageRequestStatus::Pending);

    db.set_message_request_status("c1", MessageRequestStatus::Accepted)
        .unwrap();
    assert!(db.list_pending_message_requests().unwrap().is_empty());
}

#[test]
fn devices_active_panel_and_revocation() {
    let db = open_test_db();
    db.upsert_device(&Device {
        device_id: "d1".into(),
        owner: DeviceOwner::Own,
        contact_id: None,
        name: Some("laptop".into()),
        public_key: vec![1],
        linked_at: 10,
        last_seen_at: None,
        revoked_at: None,
    })
    .unwrap();

    let own = db.list_own_devices().unwrap();
    assert_eq!(own.len(), 1);
    assert!(own[0].revoked_at.is_none());

    db.revoke_device("d1", 999).unwrap();
    let own = db.list_own_devices().unwrap();
    assert_eq!(own[0].revoked_at, Some(999));
}

#[test]
fn sessions_hold_opaque_ratchet_state() {
    let db = open_test_db();
    db.upsert_contact(&Contact {
        contact_id: "c1".into(),
        identity_public_key: vec![1],
        display_name: None,
        verified: false,
        blocked: false,
        added_at: 0,
    })
    .unwrap();

    let session = Session {
        session_id: "c1:d1".into(),
        contact_id: "c1".into(),
        device_id: "d1".into(),
        ratchet_state: vec![0xde, 0xad, 0xbe, 0xef],
        updated_at: 5,
    };
    db.upsert_session(&session).unwrap();
    assert_eq!(
        db.get_session("c1:d1").unwrap().unwrap().ratchet_state,
        vec![0xde, 0xad, 0xbe, 0xef]
    );

    db.delete_session("c1:d1").unwrap();
    assert!(db.get_session("c1:d1").unwrap().is_none());
}

#[test]
fn groups_membership_and_epoch_advance() {
    let db = open_test_db();
    for id in ["alice", "bob"] {
        db.upsert_contact(&Contact {
            contact_id: id.into(),
            identity_public_key: vec![1],
            display_name: None,
            verified: false,
            blocked: false,
            added_at: 0,
        })
        .unwrap();
    }

    db.create_group(&Group {
        group_id: "g1".into(),
        name: Some("Team".into()),
        mls_state: vec![1, 2, 3],
        epoch: 0,
        created_at: 0,
    })
    .unwrap();

    db.add_group_member("g1", "alice", 1).unwrap();
    db.add_group_member("g1", "bob", 2).unwrap();
    assert_eq!(db.list_group_members("g1").unwrap().len(), 2);

    db.remove_group_member("g1", "bob").unwrap();
    assert_eq!(db.list_group_members("g1").unwrap().len(), 1);

    db.update_group_state("g1", &[9, 9], 1).unwrap();
    let g = db.get_group("g1").unwrap().unwrap();
    assert_eq!(g.epoch, 1);
    assert_eq!(g.mls_state, vec![9, 9]);
}

#[test]
fn conversations_direct_and_group() {
    let db = open_test_db();
    db.upsert_contact(&Contact {
        contact_id: "c1".into(),
        identity_public_key: vec![1],
        display_name: None,
        verified: false,
        blocked: false,
        added_at: 0,
    })
    .unwrap();
    db.create_group(&Group {
        group_id: "g1".into(),
        name: None,
        mls_state: vec![],
        epoch: 0,
        created_at: 0,
    })
    .unwrap();

    db.create_direct_conversation("conv1", "c1", 0).unwrap();
    db.create_group_conversation("conv2", "g1", 0).unwrap();

    let convos = db.list_conversations().unwrap();
    assert_eq!(convos.len(), 2);
    assert_eq!(
        db.get_conversation("conv1").unwrap().unwrap().kind,
        ConversationKind::Direct
    );
    assert_eq!(
        db.get_conversation("conv2").unwrap().unwrap().kind,
        ConversationKind::Group
    );
}

#[test]
fn messages_listing_deletion_and_self_destruct_purge() {
    let db = open_test_db();
    db.upsert_contact(&Contact {
        contact_id: "c1".into(),
        identity_public_key: vec![1],
        display_name: None,
        verified: false,
        blocked: false,
        added_at: 0,
    })
    .unwrap();
    db.create_direct_conversation("conv1", "c1", 0).unwrap();

    db.insert_message(&Message {
        message_id: "m1".into(),
        conversation_id: "conv1".into(),
        sender_contact_id: None,
        body: Some("hello".into()),
        sent_at: 10,
        received_at: None,
        expires_at: None,
        deleted_at: None,
    })
    .unwrap();
    db.insert_message(&Message {
        message_id: "m2".into(),
        conversation_id: "conv1".into(),
        sender_contact_id: Some("c1".into()),
        body: Some("self-destructing".into()),
        sent_at: 11,
        received_at: None,
        expires_at: Some(20),
        deleted_at: None,
    })
    .unwrap();

    assert_eq!(db.list_messages("conv1", 10).unwrap().len(), 2);

    let purged = db.purge_expired_messages(25).unwrap();
    assert_eq!(purged, vec!["m2".to_string()]);
    assert_eq!(db.list_messages("conv1", 10).unwrap().len(), 1);

    db.mark_message_deleted("m1", 30).unwrap();
    assert_eq!(db.list_messages("conv1", 10).unwrap().len(), 0);
}

#[test]
fn get_messages_by_ids_fetches_only_what_was_asked_for() {
    let db = open_test_db();
    db.upsert_contact(&Contact {
        contact_id: "c1".into(),
        identity_public_key: vec![1],
        display_name: None,
        verified: false,
        blocked: false,
        added_at: 0,
    })
    .unwrap();
    db.create_direct_conversation("conv1", "c1", 0).unwrap();
    for id in ["m1", "m2", "m3"] {
        db.insert_message(&Message {
            message_id: id.into(),
            conversation_id: "conv1".into(),
            sender_contact_id: None,
            body: Some(format!("body of {id}")),
            sent_at: 0,
            received_at: None,
            expires_at: None,
            deleted_at: None,
        })
        .unwrap();
    }

    let selected = db
        .get_messages_by_ids(&["m1".to_string(), "m3".to_string()])
        .unwrap();
    let mut ids: Vec<_> = selected.iter().map(|m| m.message_id.clone()).collect();
    ids.sort();
    assert_eq!(ids, vec!["m1".to_string(), "m3".to_string()]);

    assert!(db.get_messages_by_ids(&[]).unwrap().is_empty());
}

#[test]
fn files_track_download_progress() {
    let db = open_test_db();
    db.upsert_file_meta(&FileMeta {
        content_hash: "abc123".into(),
        message_id: None,
        file_name: Some("photo.jpg".into()),
        mime_type: Some("image/jpeg".into()),
        size_bytes: 4096,
        chunk_count: 4,
        local_path: None,
        download_state: DownloadState::Pending,
    })
    .unwrap();

    db.set_download_state("abc123", DownloadState::Complete)
        .unwrap();
    assert_eq!(
        db.get_file_meta("abc123").unwrap().unwrap().download_state,
        DownloadState::Complete
    );
}

#[test]
fn settings_are_a_flat_kv_store() {
    let db = open_test_db();
    assert!(db.get_setting("cover_traffic").unwrap().is_none());
    db.set_setting("cover_traffic", "enabled").unwrap();
    assert_eq!(
        db.get_setting("cover_traffic").unwrap(),
        Some("enabled".into())
    );
}

#[test]
fn wrong_key_fails_to_open_existing_database() {
    let dir = std::env::temp_dir().join(format!("bh-storage-wrongkey-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("blackhole.db");
    let _ = std::fs::remove_file(&path);

    {
        let db = Database::open(&path, &test_key(0xAA)).unwrap();
        db.set_setting("k", "v").unwrap();
    }

    let reopened = Database::open(&path, &test_key(0xBB));
    assert!(
        reopened.is_err(),
        "opening a SQLCipher database with the wrong key must fail, not silently return garbage"
    );

    std::fs::remove_dir_all(&dir).ok();
}
