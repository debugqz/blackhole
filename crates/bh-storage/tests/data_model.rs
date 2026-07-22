use bh_storage::models::{
    AttachmentKind, Contact, ConversationKind, Device, DeviceOwner, DownloadState, FileMeta, Group,
    Message, MessageRequestStatus, MessageSticker, OwnIdentity, PaymentAsset, PaymentRequest,
    Session,
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
        broadcast_only: false,
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
        broadcast_only: false,
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
        reply_to_message_id: None,
        edited_at: None,
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
        reply_to_message_id: None,
        edited_at: None,
    })
    .unwrap();

    assert_eq!(db.list_messages("conv1", 10).unwrap().len(), 2);

    let purged = db.purge_expired_messages(25).unwrap();
    assert_eq!(purged.message_ids, vec!["m2".to_string()]);
    assert_eq!(db.list_messages("conv1", 10).unwrap().len(), 1);

    db.mark_message_deleted("m1", 30).unwrap();
    assert_eq!(db.list_messages("conv1", 10).unwrap().len(), 0);
}

/// Regression test: `files`/`payment_requests` declare `ON DELETE CASCADE`
/// against `messages`, but messages are soft-deleted (`UPDATE`, not
/// `DELETE`), so that cascade never used to fire — a "deleted"
/// self-destructing message would leave its payment address/amount/memo
/// and file key material sitting in the database untouched.
#[test]
fn deleting_a_message_scrubs_its_payment_request_and_unshared_attachment() {
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
        body: Some("pay me".into()),
        sent_at: 10,
        received_at: None,
        expires_at: Some(20),
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    })
    .unwrap();
    db.insert_payment_request(&PaymentRequest {
        message_id: "m1".into(),
        asset: PaymentAsset::Xmr,
        address: "8Addr...".into(),
        amount: Some("1.5".into()),
        memo: Some("rent".into()),
        paid_at: None,
    })
    .unwrap();
    db.upsert_file_meta(&FileMeta {
        content_hash: "hash1".into(),
        message_id: Some("m1".into()),
        file_name: Some("receipt.pdf".into()),
        mime_type: Some("application/pdf".into()),
        size_bytes: 10,
        chunk_count: 1,
        local_path: None,
        download_state: DownloadState::Complete,
        file_key: vec![7u8; 32],
        manifest_json: r#"{"total_size":10,"chunks":[]}"#.into(),
        attachment_kind: AttachmentKind::File,
        duration_secs: None,
    })
    .unwrap();

    let purged = db.purge_expired_messages(25).unwrap();
    assert_eq!(purged.message_ids, vec!["m1".to_string()]);
    assert_eq!(purged.orphaned_content_hashes, vec!["hash1".to_string()]);

    assert!(db.get_payment_request("m1").unwrap().is_none());
    assert!(db.list_files_for_conversation("conv1").unwrap().is_empty());
    assert!(db.get_file_meta("hash1").unwrap().is_none());
}

/// Companion regression test: when the same file content is attached to
/// two different messages, deleting one message must only drop *its* link
/// to the file — the file (and its key material) must survive as long as
/// another live message still references it.
#[test]
fn deleting_one_message_does_not_delete_an_attachment_still_used_by_another() {
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
    for message_id in ["m1", "m2"] {
        db.insert_message(&Message {
            message_id: message_id.into(),
            conversation_id: "conv1".into(),
            sender_contact_id: None,
            body: Some("shared file".into()),
            sent_at: 10,
            received_at: None,
            expires_at: None,
            deleted_at: None,
            reply_to_message_id: None,
            edited_at: None,
        })
        .unwrap();
        db.upsert_file_meta(&FileMeta {
            content_hash: "shared-hash".into(),
            message_id: Some(message_id.into()),
            file_name: Some("photo.jpg".into()),
            mime_type: Some("image/jpeg".into()),
            size_bytes: 10,
            chunk_count: 1,
            local_path: None,
            download_state: DownloadState::Complete,
            file_key: vec![7u8; 32],
            manifest_json: r#"{"total_size":10,"chunks":[]}"#.into(),
            attachment_kind: AttachmentKind::File,
            duration_secs: None,
        })
        .unwrap();
    }

    db.mark_message_deleted("m1", 30).unwrap();

    // m1's link to the shared file is gone, but m2 still needs it, so the
    // underlying file row must still exist.
    assert!(db.get_file_meta("shared-hash").unwrap().is_some());
    let remaining = db.list_files_for_conversation("conv1").unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].message_id.as_deref(), Some("m2"));

    db.mark_message_deleted("m2", 31).unwrap();
    assert!(db.get_file_meta("shared-hash").unwrap().is_none());
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
            reply_to_message_id: None,
            edited_at: None,
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
        file_key: vec![0u8; 32],
        manifest_json: "{}".into(),
        attachment_kind: AttachmentKind::File,
        duration_secs: None,
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
/// A linked device's sync cursor starts unset, advances monotonically,
/// and `list_messages_since` returns exactly the messages sent strictly
/// after the cursor — including a self-destructed one (body already
/// wiped), so a device syncing after a message expires doesn't stall on
/// it forever.
#[test]
fn device_sync_cursor_and_messages_since() {
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
    db.upsert_device(&Device {
        device_id: "d2".into(),
        owner: DeviceOwner::Own,
        contact_id: None,
        name: Some("phone".into()),
        public_key: vec![2],
        linked_at: 5,
        last_seen_at: None,
        revoked_at: None,
    })
    .unwrap();

    assert!(db.get_device_sync_cursor("d2").unwrap().is_none());

    db.insert_message(&Message {
        message_id: "m1".into(),
        conversation_id: "conv1".into(),
        sender_contact_id: None,
        body: Some("hi".into()),
        sent_at: 10,
        received_at: None,
        expires_at: None,
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    })
    .unwrap();
    db.insert_message(&Message {
        message_id: "m2".into(),
        conversation_id: "conv1".into(),
        sender_contact_id: Some("c1".into()),
        body: Some("there".into()),
        sent_at: 11,
        received_at: None,
        expires_at: None,
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    })
    .unwrap();

    let pending = db.list_messages_since(0, None, 100).unwrap();
    assert_eq!(
        pending
            .iter()
            .map(|m| m.message_id.as_str())
            .collect::<Vec<_>>(),
        vec!["m1", "m2"]
    );

    db.advance_device_sync_cursor("d2", 10, "m1", 100).unwrap();
    assert_eq!(
        db.get_device_sync_cursor("d2").unwrap(),
        Some((10, Some("m1".to_string())))
    );

    // Only m2 is left after the cursor advances past m1.
    let remaining = db.list_messages_since(10, Some("m1"), 100).unwrap();
    assert_eq!(
        remaining
            .iter()
            .map(|m| m.message_id.as_str())
            .collect::<Vec<_>>(),
        vec!["m2"]
    );

    // A self-destructed message still counts (and still advances the
    // cursor), even though its body is gone.
    db.mark_message_deleted("m2", 20).unwrap();
    let remaining = db.list_messages_since(10, Some("m1"), 100).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].body, None);

    db.advance_device_sync_cursor("d2", 11, "m2", 101).unwrap();
    assert!(db
        .list_messages_since(11, Some("m2"), 100)
        .unwrap()
        .is_empty());
}

/// A message's sticker is a message-lifetime side table, same as its
/// payment request — deleting/self-destructing the message must scrub it.
#[test]
fn deleting_a_message_scrubs_its_sticker() {
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
        body: None,
        sent_at: 10,
        received_at: None,
        expires_at: None,
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    })
    .unwrap();
    db.insert_message_sticker(&MessageSticker {
        message_id: "m1".into(),
        pack_item_id: "sticker-pack-nebula".into(),
        sticker_id: "nebula-wave".into(),
    })
    .unwrap();
    assert!(db.get_message_sticker("m1").unwrap().is_some());

    db.mark_message_deleted("m1", 100).unwrap();
    assert!(db.get_message_sticker("m1").unwrap().is_none());
}

/// The singleton local "Notes to self" conversation: idempotent to create,
/// no counterparty (`contact_id`/`group_id` both `None`), and messages can
/// still be inserted/listed into it exactly like any other conversation.
#[test]
fn self_conversation_is_a_singleton_with_no_counterparty() {
    let db = open_test_db();

    let first = db.ensure_self_conversation(1000).unwrap();
    assert_eq!(first.kind, ConversationKind::SelfNotes);
    assert!(first.contact_id.is_none());
    assert!(first.group_id.is_none());
    assert_eq!(first.created_at, 1000);

    // Idempotent: a second call (even with a different timestamp, as
    // happens when both identity bootstrap and a later `GET
    // /conversations` both call it) returns the same row rather than
    // creating a second one.
    let second = db.ensure_self_conversation(2000).unwrap();
    assert_eq!(second.conversation_id, first.conversation_id);
    assert_eq!(second.created_at, first.created_at);

    let self_conversations: Vec<_> = db
        .list_conversations()
        .unwrap()
        .into_iter()
        .filter(|c| c.kind == ConversationKind::SelfNotes)
        .collect();
    assert_eq!(
        self_conversations.len(),
        1,
        "exactly one self-conversation must exist, no matter how many times ensure_self_conversation is called"
    );

    // No contact, no session — a self-note can still be sent and read.
    db.insert_message(&Message {
        message_id: "note1".into(),
        conversation_id: first.conversation_id.clone(),
        sender_contact_id: None,
        body: Some("buy milk".into()),
        sent_at: 3000,
        received_at: None,
        expires_at: None,
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    })
    .unwrap();
    let notes = db.list_messages(&first.conversation_id, 10).unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].body, Some("buy milk".to_string()));
}

/// Editing a message archives the previous body into `message_edits`
/// (tagged with when that version became current) instead of silently
/// overwriting it, history stays in chronological order across multiple
/// edits, and editing a nonexistent or already-deleted message is a no-op.
#[test]
fn editing_a_message_preserves_history_instead_of_overwriting() {
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
        reply_to_message_id: None,
        edited_at: None,
    })
    .unwrap();

    // No edits yet.
    assert!(db.list_message_edits("m1").unwrap().is_empty());

    let edited = db.edit_message("m1", "hello there", 20).unwrap().unwrap();
    assert_eq!(edited.body, Some("hello there".into()));
    assert_eq!(edited.edited_at, Some(20));

    // The original body is preserved, tagged with when it was current
    // (sent_at, since this is the first edit).
    let history = db.list_message_edits("m1").unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body, Some("hello".into()));
    assert_eq!(history[0].edited_at, 10);

    // A second edit archives the *second* version too, and history stays
    // in chronological order (oldest first).
    let edited_again = db.edit_message("m1", "hello there!!", 30).unwrap().unwrap();
    assert_eq!(edited_again.body, Some("hello there!!".into()));
    assert_eq!(edited_again.edited_at, Some(30));

    let history = db.list_message_edits("m1").unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].body, Some("hello".into()));
    assert_eq!(history[0].edited_at, 10);
    assert_eq!(history[1].body, Some("hello there".into()));
    assert_eq!(history[1].edited_at, 20);

    // Editing a nonexistent message is a no-op, not an error.
    assert!(db.edit_message("nope", "x", 40).unwrap().is_none());

    // A deleted message can't be edited back to life.
    db.mark_message_deleted("m1", 50).unwrap();
    assert!(db.edit_message("m1", "resurrected", 60).unwrap().is_none());
}

/// Typing indicators default to off on a fresh database (no explicit row
/// yet) and are toggleable — the opt-in contract requires a positive
/// action to turn them on, never a default-on gap.
#[test]
fn typing_indicators_default_off_and_are_toggleable() {
    let db = open_test_db();
    assert!(!db.typing_indicators_enabled().unwrap());

    db.set_typing_indicators_enabled(true).unwrap();
    assert!(db.typing_indicators_enabled().unwrap());

    db.set_typing_indicators_enabled(false).unwrap();
    assert!(!db.typing_indicators_enabled().unwrap());
}

/// A group's `broadcast_only` flag persists and is reachable both directly
/// (`get_group`) and via its backing conversation (`get_group_for_conversation`,
/// which `send_message` uses to decide whether the posting restriction
/// applies) — a direct conversation has no backing group at all.
#[test]
fn broadcast_channel_flag_persists_and_is_reachable_via_its_conversation() {
    let db = open_test_db();
    db.upsert_contact(&Contact {
        contact_id: "alice".into(),
        identity_public_key: vec![1],
        display_name: None,
        verified: false,
        blocked: false,
        added_at: 0,
    })
    .unwrap();

    db.create_group(&Group {
        group_id: "chan1".into(),
        name: Some("Announcements".into()),
        mls_state: vec![],
        epoch: 0,
        created_at: 0,
        broadcast_only: true,
    })
    .unwrap();
    db.add_group_member("chan1", "alice", 0).unwrap();
    db.create_group_conversation("conv1", "chan1", 0).unwrap();

    let group = db.get_group("chan1").unwrap().unwrap();
    assert!(group.broadcast_only);

    // A normal group, for contrast — the same lookup returns `false`.
    db.create_group(&Group {
        group_id: "grp1".into(),
        name: Some("Friends".into()),
        mls_state: vec![],
        epoch: 0,
        created_at: 0,
        broadcast_only: false,
    })
    .unwrap();
    db.create_group_conversation("conv2", "grp1", 0).unwrap();

    let via_conv1 = db.get_group_for_conversation("conv1").unwrap().unwrap();
    assert!(via_conv1.broadcast_only);
    let via_conv2 = db.get_group_for_conversation("conv2").unwrap().unwrap();
    assert!(!via_conv2.broadcast_only);

    // A direct (non-group) conversation has no backing group at all.
    db.create_direct_conversation("conv3", "alice", 0).unwrap();
    assert!(db.get_group_for_conversation("conv3").unwrap().is_none());
}

#[test]
fn search_messages_finds_matches_and_respects_deletion_and_scope() {
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
    db.upsert_contact(&Contact {
        contact_id: "c2".into(),
        identity_public_key: vec![2],
        display_name: None,
        verified: false,
        blocked: false,
        added_at: 0,
    })
    .unwrap();
    db.create_direct_conversation("conv1", "c1", 0).unwrap();
    db.create_direct_conversation("conv2", "c2", 0).unwrap();

    db.insert_message(&Message {
        message_id: "m1".into(),
        conversation_id: "conv1".into(),
        sender_contact_id: None,
        body: Some("let's grab pancakes tomorrow".into()),
        sent_at: 10,
        received_at: None,
        expires_at: None,
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    })
    .unwrap();
    db.insert_message(&Message {
        message_id: "m2".into(),
        conversation_id: "conv1".into(),
        sender_contact_id: Some("c1".into()),
        body: Some("no thanks, not hungry".into()),
        sent_at: 11,
        received_at: None,
        expires_at: None,
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    })
    .unwrap();
    db.insert_message(&Message {
        message_id: "m3".into(),
        conversation_id: "conv2".into(),
        sender_contact_id: Some("c2".into()),
        body: Some("pancakes sound great actually".into()),
        sent_at: 12,
        received_at: None,
        expires_at: None,
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    })
    .unwrap();

    // Matches across every conversation, most recent first.
    let results = db.search_messages("pancakes", None, 10).unwrap();
    let ids: Vec<_> = results.iter().map(|r| r.message_id.clone()).collect();
    assert_eq!(ids, vec!["m3".to_string(), "m1".to_string()]);
    assert!(results[0].snippet.contains('[') && results[0].snippet.contains(']'));

    // Scoped to a single conversation.
    let scoped = db.search_messages("pancakes", Some("conv1"), 10).unwrap();
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].message_id, "m1");

    // A term that isn't present anywhere returns nothing.
    assert!(db.search_messages("volcano", None, 10).unwrap().is_empty());

    // Deleting the message removes it from the index (the FTS5 sync
    // trigger fires on the `body = NULL` update `mark_message_deleted`
    // does), so a subsequent search no longer finds it.
    db.mark_message_deleted("m1", 20).unwrap();
    let after_delete = db.search_messages("pancakes", None, 10).unwrap();
    assert_eq!(after_delete.len(), 1);
    assert_eq!(after_delete[0].message_id, "m3");

    // Blank/whitespace-only queries are treated as "no search," not "match
    // everything."
    assert!(db.search_messages("", None, 10).unwrap().is_empty());
    assert!(db.search_messages("   ", None, 10).unwrap().is_empty());
}

#[test]
fn search_messages_treats_punctuation_as_literal_text_not_fts5_syntax() {
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
        body: Some("call me at 555-1234 not:now".into()),
        sent_at: 10,
        received_at: None,
        expires_at: None,
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    })
    .unwrap();

    // A query containing FTS5-special characters (quotes, hyphens, `NOT`,
    // `:`) must neither error out nor be reinterpreted as FTS5 query
    // syntax — it should either match as literal text or safely find
    // nothing, but never bubble up a syntax error.
    for query in ["555-1234", "\"quoted\"", "NOT now", "a:b"] {
        assert!(db.search_messages(query, None, 10).is_ok());
    }
}
