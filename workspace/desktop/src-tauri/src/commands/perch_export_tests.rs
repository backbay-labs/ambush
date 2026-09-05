use super::*;

#[test]
fn a_bundle_path_that_climbs_is_refused_rather_than_cleaned() {
    // A "cleaned" path that still resolves somewhere unexpected is the shape
    // of every traversal bug, and the caller here is a webview.
    for path in [
        "../escape.json",
        "receipts/../../escape.json",
        "/etc/passwd",
        "",
    ] {
        assert!(
            safe_relative(path).is_err(),
            "path {path:?} must be refused"
        );
    }
}

#[test]
fn ordinary_bundle_paths_are_accepted() {
    for path in ["receipts/r1.json", "envelopes/.keep", "VERIFY.md"] {
        assert!(
            safe_relative(path).is_ok(),
            "path {path:?} must be accepted"
        );
    }
}

#[test]
fn writing_creates_the_nested_directories_the_layout_needs() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let outcome = write_bundle(
        dir.path(),
        &[
            (PathBuf::from("receipts/r1.json"), b"{\"a\":1}".to_vec()),
            (PathBuf::from("envelopes/.keep"), Vec::new()),
            (PathBuf::from("VERIFY.md"), b"# VERIFY".to_vec()),
        ],
    )
    .expect("written");

    assert_eq!(outcome.written.len(), 3);
    // 7 for the receipt, 8 for VERIFY.md, and 0 for the empty `.keep` — which
    // is counted as a file even though it contributes no bytes.
    assert_eq!(outcome.bytes, 15);
    assert_eq!(
        std::fs::read(dir.path().join("receipts/r1.json")).unwrap(),
        b"{\"a\":1}"
    );
    // `envelopes/` present and EMPTY says "we looked and there was nothing
    // signed"; an absent directory would read as "we did not look".
    assert!(dir.path().join("envelopes/.keep").exists());
}

#[test]
fn the_bytes_are_written_verbatim() {
    // Re-serializing would change the digest of a signed record and turn a
    // verifiable artifact into this console's paraphrase of one.
    let dir = tempfile::tempdir().expect("a temp dir");
    let exact = b"{\"schema\":\"swarm.spine.envelope.v1\",\"seq\":41}".to_vec();
    write_bundle(
        dir.path(),
        &[(PathBuf::from("envelopes/e.json"), exact.clone())],
    )
    .expect("written");
    assert_eq!(
        std::fs::read(dir.path().join("envelopes/e.json")).unwrap(),
        exact
    );
}

#[tokio::test]
async fn an_empty_bundle_is_refused() {
    // A directory that looks like evidence and answers nothing is worse than
    // an error an operator can read.
    let dir = tempfile::tempdir().expect("a temp dir");
    let error = perch_export_bundle(dir.path().to_string_lossy().into_owned(), Vec::new())
        .await
        .expect_err("an empty bundle must be refused");
    assert!(error.contains("answers nothing"), "{error}");
}

#[tokio::test]
async fn a_bad_path_writes_nothing_at_all() {
    // Every path is validated before anything is written: a bundle that failed
    // halfway would leave a partial directory an operator might ship.
    use base64::Engine as _;
    let dir = tempfile::tempdir().expect("a temp dir");
    let good = base64::engine::general_purpose::STANDARD.encode(b"ok");
    let result = perch_export_bundle(
        dir.path().to_string_lossy().into_owned(),
        vec![
            PerchExportFile {
                path: "receipts/first.json".into(),
                bytes_b64: good.clone(),
            },
            PerchExportFile {
                path: "../escape.json".into(),
                bytes_b64: good,
            },
        ],
    )
    .await;
    assert!(result.is_err());
    assert!(
        !dir.path().join("receipts/first.json").exists(),
        "the valid file must not have been written before the invalid one was rejected"
    );
}

#[tokio::test]
async fn bytes_that_are_not_base64_are_refused() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let error = perch_export_bundle(
        dir.path().to_string_lossy().into_owned(),
        vec![PerchExportFile {
            path: "a.json".into(),
            bytes_b64: "not base64!!".into(),
        }],
    )
    .await
    .expect_err("refused");
    assert!(error.contains("not base64"), "{error}");
}
