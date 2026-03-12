// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Integration tests for the NOA checkpoint pipeline:
//! `NOACheckpointSubmitter` → `NOACheckpointLocalStore` → `NOACheckpointCertifier`.
//!
//! These tests verify the channel-based NOA checkpoint flow without requiring
//! the full MPC infrastructure. Sign outputs are simulated.

mod tests {
    use std::sync::Arc;

    use dwallet_mpc_types::dwallet_mpc::{
        DWalletCurve, DWalletHashScheme, DWalletSignatureAlgorithm,
    };
    use ika_types::message::DWalletCheckpointMessageKind;
    use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
    use ika_types::messages_system_checkpoints::SystemCheckpointMessageKind;
    use ika_types::noa_checkpoint::{
        self, NOACheckpointKind, NOACheckpointKindName, NOACheckpointMessage, SuiChainContext,
    };
    use tokio::sync::mpsc;

    use crate::dwallet_mpc::{NetworkOwnedAddressSignOutput, NetworkOwnedAddressSignRequest};

    fn test_session_id() -> SessionIdentifier {
        SessionIdentifier::new(SessionType::System, [0u8; SessionIdentifier::LENGTH])
    }

    fn test_sui_chain_context() -> SuiChainContext {
        SuiChainContext {
            reference_gas_price: 1000,
            sui_epoch: 1,
        }
    }

    use crate::noa_checkpoints::checkpoint_output::{
        CertifiedNOACheckpointOutput, LogNOACheckpointOutput,
    };
    use crate::noa_checkpoints::{
        NOACheckpointCertifier, NOACheckpointLocalStore, NOACheckpointSubmitter,
    };

    // =========================================================================
    // NOACheckpointLocalStore unit tests
    // =========================================================================

    #[test]
    fn test_local_store_single_tx_checkpoint() {
        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();

        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        let tx_data = vec![(b"tx_data_0".to_vec(), vec![])];
        store.insert_pending(0, checkpoint, tx_data);

        // Signature for unknown bytes returns None.
        assert!(
            store
                .add_signature(
                    b"unknown",
                    b"sig".to_vec(),
                    DWalletCurve::Curve25519,
                    DWalletSignatureAlgorithm::EdDSA,
                )
                .is_none()
        );

        // Correct signature completes the checkpoint.
        let certified = store.add_signature(
            b"tx_data_0",
            b"signature_0".to_vec(),
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        assert!(certified.is_some());
        let certified = certified.unwrap();
        assert_eq!(certified.checkpoint.epoch, 1);
        assert_eq!(certified.checkpoint.sequence_number, 0);
        assert_eq!(certified.signatures.len(), 1);
        assert_eq!(certified.signatures[0], b"signature_0");
        assert_eq!(certified.signed_bytes, vec![b"tx_data_0".to_vec()]);
    }

    #[test]
    fn test_local_store_multi_tx_checkpoint() {
        let store = NOACheckpointLocalStore::<noa_checkpoint::System>::new();

        let checkpoint = NOACheckpointMessage {
            epoch: 2,
            sequence_number: 5,
            messages: vec![],
        };
        let tx_data = vec![
            (b"tx_a".to_vec(), vec![]),
            (b"tx_b".to_vec(), vec![]),
            (b"tx_c".to_vec(), vec![]),
        ];
        store.insert_pending(5, checkpoint, tx_data);

        // First two signatures: checkpoint should not be complete yet.
        assert!(
            store
                .add_signature(
                    b"tx_a",
                    b"sig_a".to_vec(),
                    DWalletCurve::Curve25519,
                    DWalletSignatureAlgorithm::EdDSA,
                )
                .is_none()
        );
        assert!(
            store
                .add_signature(
                    b"tx_c",
                    b"sig_c".to_vec(),
                    DWalletCurve::Curve25519,
                    DWalletSignatureAlgorithm::EdDSA,
                )
                .is_none()
        );

        // Third signature completes the checkpoint.
        let certified = store
            .add_signature(
                b"tx_b",
                b"sig_b".to_vec(),
                DWalletCurve::Curve25519,
                DWalletSignatureAlgorithm::EdDSA,
            )
            .expect("should certify after all tx's signed");

        assert_eq!(certified.checkpoint.sequence_number, 5);
        // Signatures must be in the same order as the original tx_bytes.
        assert_eq!(
            certified.signatures,
            vec![b"sig_a".to_vec(), b"sig_b".to_vec(), b"sig_c".to_vec(),]
        );
        assert_eq!(
            certified.signed_bytes,
            vec![b"tx_a".to_vec(), b"tx_b".to_vec(), b"tx_c".to_vec(),]
        );
    }

    #[test]
    fn test_local_store_multiple_checkpoints() {
        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();

        // Insert two checkpoints with different sequence numbers.
        let first = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, first, vec![(b"first_tx".to_vec(), vec![])]);

        let second = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 1,
            messages: vec![],
        };
        store.insert_pending(1, second, vec![(b"second_tx".to_vec(), vec![])]);

        // Complete checkpoint 1 before checkpoint 0.
        let cert_second = store.add_signature(
            b"second_tx",
            b"sig_second".to_vec(),
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        assert!(cert_second.is_some());
        assert_eq!(cert_second.unwrap().checkpoint.sequence_number, 1);

        // Checkpoint 0 is still pending.
        let cert_first = store.add_signature(
            b"first_tx",
            b"sig_first".to_vec(),
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        assert!(cert_first.is_some());
        assert_eq!(cert_first.unwrap().checkpoint.sequence_number, 0);
    }

    #[test]
    fn test_local_store_certified_stored_by_add_signature() {
        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();

        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(b"tx".to_vec(), vec![])]);
        let certified = store
            .add_signature(
                b"tx",
                b"sig".to_vec(),
                DWalletCurve::Curve25519,
                DWalletSignatureAlgorithm::EdDSA,
            )
            .unwrap();

        // add_signature stores the certified checkpoint directly — no separate insert needed.
        let retrieved = store.get_certified(0);
        assert!(retrieved.is_some());
        assert_eq!(
            retrieved.unwrap().checkpoint.sequence_number,
            certified.checkpoint.sequence_number
        );

        // Non-existent sequence number returns None.
        assert!(store.get_certified(99).is_none());
    }

    #[test]
    fn test_local_store_cleanup_after_certification() {
        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();

        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(b"tx".to_vec(), vec![])]);

        // Complete the checkpoint.
        store.add_signature(
            b"tx",
            b"sig".to_vec(),
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );

        // After certification, submitting the same tx_bytes should return None
        // because the tx_to_seq mapping was cleaned up.
        assert!(
            store
                .add_signature(
                    b"tx",
                    b"sig_again".to_vec(),
                    DWalletCurve::Curve25519,
                    DWalletSignatureAlgorithm::EdDSA,
                )
                .is_none()
        );
    }

    #[test]
    fn test_local_store_duplicate_signature_ignored() {
        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();

        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(
            0,
            checkpoint,
            vec![(b"tx_a".to_vec(), vec![]), (b"tx_b".to_vec(), vec![])],
        );

        // Sign tx_a — tx_to_seq entry removed per-tx.
        store.add_signature(
            b"tx_a",
            b"sig_1".to_vec(),
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        // Second call for tx_a: tx_to_seq lookup fails, duplicate is silently ignored.
        assert!(
            store
                .add_signature(
                    b"tx_a",
                    b"sig_overwrite".to_vec(),
                    DWalletCurve::Curve25519,
                    DWalletSignatureAlgorithm::EdDSA,
                )
                .is_none()
        );

        // Complete with tx_b.
        let certified = store.add_signature(
            b"tx_b",
            b"sig_b".to_vec(),
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        assert!(certified.is_some());
        // The first signature for tx_a is preserved (duplicate was ignored).
        assert_eq!(certified.unwrap().signatures[0], b"sig_1");
    }

    // =========================================================================
    // NOACheckpointSubmitter async tests
    // =========================================================================

    #[tokio::test]
    async fn test_submitter_sends_sign_requests() {
        let store = Arc::new(NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new());
        let (sign_tx, mut sign_rx) = mpsc::unbounded_channel::<NetworkOwnedAddressSignRequest>();
        let (msg_tx, msg_rx) =
            mpsc::channel::<(Vec<DWalletCheckpointMessageKind>, SuiChainContext)>(16);

        let submitter = NOACheckpointSubmitter::<noa_checkpoint::DWallet>::new(
            msg_rx,
            sign_tx,
            store.clone(),
            1,
            vec![],
        );

        // Spawn the submitter in the background.
        let handle = tokio::spawn(submitter.run());

        // Send checkpoint messages bundled with chain context.
        let ctx = test_sui_chain_context();
        msg_tx
            .send((vec![], ctx.clone()))
            .await
            .expect("send should succeed");
        msg_tx
            .send((vec![], ctx))
            .await
            .expect("send should succeed");

        // Drop sender to close the channel and let the submitter exit.
        drop(msg_tx);
        handle.await.expect("submitter should complete");

        // We should have received exactly 2 sign requests (one per checkpoint, each with 1 tx).
        let mut requests = Vec::new();
        while let Ok(req) = sign_rx.try_recv() {
            requests.push(req);
        }
        assert_eq!(requests.len(), 2, "should have 2 sign requests");

        // Both should use DWallet's curve/algorithm/hash.
        for req in &requests {
            assert_eq!(req.curve, noa_checkpoint::DWallet::curve());
            assert_eq!(
                req.signature_algorithm,
                noa_checkpoint::DWallet::signature_algorithm()
            );
            assert_eq!(req.hash_scheme, noa_checkpoint::DWallet::hash_scheme());
        }

        // Messages should be different (different sequence numbers → different signable bytes).
        assert_ne!(
            requests[0].message, requests[1].message,
            "different checkpoints should produce different tx bytes"
        );

        // Store should have 2 pending checkpoints.
        assert!(store.get_certified(0).is_none(), "not yet certified");
        assert!(store.get_certified(1).is_none(), "not yet certified");
    }

    #[tokio::test]
    async fn test_submitter_monotonic_sequence_numbers() {
        let store = Arc::new(NOACheckpointLocalStore::<noa_checkpoint::System>::new());
        let (sign_tx, _sign_rx) = mpsc::unbounded_channel::<NetworkOwnedAddressSignRequest>();
        let (msg_tx, msg_rx) =
            mpsc::channel::<(Vec<SystemCheckpointMessageKind>, SuiChainContext)>(16);

        let submitter = NOACheckpointSubmitter::<noa_checkpoint::System>::new(
            msg_rx,
            sign_tx,
            store.clone(),
            42,
            vec![],
        );

        let handle = tokio::spawn(submitter.run());

        let ctx = test_sui_chain_context();
        for _ in 0..5 {
            msg_tx.send((vec![], ctx.clone())).await.unwrap();
        }
        drop(msg_tx);
        handle.await.unwrap();

        // Verify each checkpoint got a monotonically increasing sequence number
        // by checking the pending store for entries 0..5.
        // Since nothing has been signed, all should still be pending.
        // We verify by trying to sign each one — the tx_bytes are signable_bytes output.
        for seq in 0..5u64 {
            let checkpoint = NOACheckpointMessage::<noa_checkpoint::System> {
                epoch: 42,
                sequence_number: seq,
                messages: vec![],
            };
            let expected_bytes = vec![noa_checkpoint::System::build_tx_bytes(
                checkpoint.epoch,
                checkpoint.sequence_number,
                0,
                &checkpoint.messages,
                &test_sui_chain_context(),
                &[],
                0,
            )];
            // Signing should find the pending entry.
            let result = store.add_signature(
                &expected_bytes[0],
                b"test_sig".to_vec(),
                DWalletCurve::Curve25519,
                DWalletSignatureAlgorithm::EdDSA,
            );
            assert!(
                result.is_some(),
                "checkpoint seq={seq} should be pending in store"
            );
            assert_eq!(result.unwrap().checkpoint.sequence_number, seq);
        }
    }

    // =========================================================================
    // NOACheckpointCertifier async tests
    // =========================================================================

    #[tokio::test]
    async fn test_certifier_collects_signatures_and_certifies() {
        let store = Arc::new(NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new());
        let (output_tx, output_rx) = mpsc::channel::<NetworkOwnedAddressSignOutput>(16);

        let certified_output = Box::new(LogNOACheckpointOutput);
        let certifier = NOACheckpointCertifier::<noa_checkpoint::DWallet>::new(
            store.clone(),
            output_rx,
            certified_output,
        );

        // Pre-populate the store with a pending checkpoint.
        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        let tx_bytes = b"certifier_test_tx".to_vec();
        store.insert_pending(0, checkpoint, vec![(tx_bytes.clone(), vec![])]);

        let handle = tokio::spawn(certifier.run());

        // Send a simulated sign output.
        output_tx
            .send(NetworkOwnedAddressSignOutput {
                session_identifier: test_session_id(),
                message: tx_bytes.clone(),
                signature: b"mpc_signature".to_vec(),
                curve: DWalletCurve::Curve25519,
                signature_algorithm: DWalletSignatureAlgorithm::EdDSA,
                hash_scheme: DWalletHashScheme::SHA512,
            })
            .await
            .unwrap();

        // Give the certifier a moment to process.
        tokio::task::yield_now().await;

        // Drop sender to shut down the certifier.
        drop(output_tx);
        handle.await.unwrap();

        // Verify the checkpoint was certified and stored (by add_signature directly).
        let certified = store.get_certified(0).expect("should be certified");
        assert_eq!(certified.checkpoint.sequence_number, 0);
        assert_eq!(certified.signatures, vec![b"mpc_signature".to_vec()]);
        assert_eq!(certified.signed_bytes, vec![tx_bytes]);
    }

    #[tokio::test]
    async fn test_certifier_ignores_unknown_sign_outputs() {
        let store = Arc::new(NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new());
        let (output_tx, output_rx) = mpsc::channel::<NetworkOwnedAddressSignOutput>(16);

        let certifier = NOACheckpointCertifier::<noa_checkpoint::DWallet>::new(
            store.clone(),
            output_rx,
            Box::new(LogNOACheckpointOutput),
        );

        let handle = tokio::spawn(certifier.run());

        // Send an output for a non-existent checkpoint — should be silently ignored.
        output_tx
            .send(NetworkOwnedAddressSignOutput {
                session_identifier: test_session_id(),
                message: b"unknown_tx".to_vec(),
                signature: b"sig".to_vec(),
                curve: DWalletCurve::Curve25519,
                signature_algorithm: DWalletSignatureAlgorithm::EdDSA,
                hash_scheme: DWalletHashScheme::SHA512,
            })
            .await
            .unwrap();

        tokio::task::yield_now().await;
        drop(output_tx);
        handle.await.unwrap();

        // No certified checkpoints should exist.
        assert!(store.get_certified(0).is_none());
    }

    // =========================================================================
    // End-to-end pipeline: Submitter → Store → Certifier
    // =========================================================================

    #[tokio::test]
    async fn test_end_to_end_submitter_to_certifier_pipeline() {
        let store = Arc::new(NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new());

        // Channels: msg_tx → Submitter → sign_request_tx/rx → (simulated MPC) → output_tx → Certifier
        let (msg_tx, msg_rx) =
            mpsc::channel::<(Vec<DWalletCheckpointMessageKind>, SuiChainContext)>(16);
        let (sign_request_tx, mut sign_request_rx) =
            mpsc::unbounded_channel::<NetworkOwnedAddressSignRequest>();
        let (sign_output_tx, sign_output_rx) = mpsc::channel::<NetworkOwnedAddressSignOutput>(16);

        // Spawn submitter.
        let submitter = NOACheckpointSubmitter::<noa_checkpoint::DWallet>::new(
            msg_rx,
            sign_request_tx,
            store.clone(),
            7,
            vec![],
        );
        let submitter_handle = tokio::spawn(submitter.run());

        // Spawn certifier.
        let certifier = NOACheckpointCertifier::<noa_checkpoint::DWallet>::new(
            store.clone(),
            sign_output_rx,
            Box::new(LogNOACheckpointOutput),
        );
        let certifier_handle = tokio::spawn(certifier.run());

        // Send 3 checkpoints.
        let ctx = test_sui_chain_context();
        for _ in 0..3 {
            msg_tx.send((vec![], ctx.clone())).await.unwrap();
        }
        // Close msg channel so submitter can finish producing requests then exit.
        drop(msg_tx);
        submitter_handle.await.unwrap();

        // Simulate MPC signing: read all sign requests and produce sign outputs.
        let mut sign_requests = Vec::new();
        while let Ok(req) = sign_request_rx.try_recv() {
            sign_requests.push(req);
        }
        assert_eq!(sign_requests.len(), 3, "one sign request per checkpoint");

        for req in &sign_requests {
            sign_output_tx
                .send(NetworkOwnedAddressSignOutput {
                    session_identifier: test_session_id(),
                    message: req.message.clone(),
                    signature: format!(
                        "sig_for_{}",
                        hex::encode(&req.message[..8.min(req.message.len())])
                    )
                    .into_bytes(),
                    curve: req.curve,
                    signature_algorithm: req.signature_algorithm,
                    hash_scheme: req.hash_scheme,
                })
                .await
                .unwrap();
        }

        // Close output channel so certifier can finish.
        drop(sign_output_tx);
        certifier_handle.await.unwrap();

        // All 3 checkpoints should be certified.
        for seq in 0..3u64 {
            let certified = store
                .get_certified(seq)
                .unwrap_or_else(|| panic!("checkpoint seq={seq} should be certified"));
            assert_eq!(certified.checkpoint.epoch, 7);
            assert_eq!(certified.checkpoint.sequence_number, seq);
            assert_eq!(certified.signatures.len(), 1);
            assert!(!certified.signatures[0].is_empty());
        }
    }

    #[tokio::test]
    async fn test_end_to_end_system_checkpoint_pipeline() {
        let store = Arc::new(NOACheckpointLocalStore::<noa_checkpoint::System>::new());

        let (msg_tx, msg_rx) =
            mpsc::channel::<(Vec<SystemCheckpointMessageKind>, SuiChainContext)>(16);
        let (sign_request_tx, mut sign_request_rx) =
            mpsc::unbounded_channel::<NetworkOwnedAddressSignRequest>();
        let (sign_output_tx, sign_output_rx) = mpsc::channel::<NetworkOwnedAddressSignOutput>(16);

        let submitter = NOACheckpointSubmitter::<noa_checkpoint::System>::new(
            msg_rx,
            sign_request_tx,
            store.clone(),
            3,
            vec![],
        );
        let submitter_handle = tokio::spawn(submitter.run());

        let certifier = NOACheckpointCertifier::<noa_checkpoint::System>::new(
            store.clone(),
            sign_output_rx,
            Box::new(LogNOACheckpointOutput),
        );
        let certifier_handle = tokio::spawn(certifier.run());

        // Send a system checkpoint with a real message.
        msg_tx
            .send((
                vec![SystemCheckpointMessageKind::EndOfPublish],
                test_sui_chain_context(),
            ))
            .await
            .unwrap();
        drop(msg_tx);
        submitter_handle.await.unwrap();

        // Simulate signing.
        let req = sign_request_rx
            .try_recv()
            .expect("should have a sign request");
        assert_eq!(req.curve, noa_checkpoint::System::curve());

        sign_output_tx
            .send(NetworkOwnedAddressSignOutput {
                session_identifier: test_session_id(),
                message: req.message.clone(),
                signature: b"system_sig".to_vec(),
                curve: req.curve,
                signature_algorithm: req.signature_algorithm,
                hash_scheme: req.hash_scheme,
            })
            .await
            .unwrap();
        drop(sign_output_tx);
        certifier_handle.await.unwrap();

        let certified = store.get_certified(0).expect("should be certified");
        assert_eq!(certified.checkpoint.epoch, 3);
        assert_eq!(
            certified.checkpoint.messages,
            vec![SystemCheckpointMessageKind::EndOfPublish]
        );
        assert_eq!(certified.signatures, vec![b"system_sig".to_vec()]);
    }

    // =========================================================================
    // Custom CertifiedNOACheckpointOutput for testing
    // =========================================================================

    /// Collects certified checkpoints into a shared vec for assertion.
    struct CollectingOutput<K: NOACheckpointKind> {
        collected: Arc<
            parking_lot::Mutex<Vec<ika_types::noa_checkpoint::CertifiedNOACheckpointMessage<K>>>,
        >,
    }

    impl<K: NOACheckpointKind> CertifiedNOACheckpointOutput<K> for CollectingOutput<K> {
        fn certified_checkpoint_created(
            &self,
            checkpoint: &ika_types::noa_checkpoint::CertifiedNOACheckpointMessage<K>,
        ) -> ika_types::error::IkaResult {
            self.collected.lock().push(checkpoint.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_certifier_invokes_output_handler() {
        let store = Arc::new(NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new());
        let (output_tx, output_rx) = mpsc::channel::<NetworkOwnedAddressSignOutput>(16);

        let collected = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let output_handler = Box::new(CollectingOutput::<noa_checkpoint::DWallet> {
            collected: collected.clone(),
        });

        let certifier = NOACheckpointCertifier::<noa_checkpoint::DWallet>::new(
            store.clone(),
            output_rx,
            output_handler,
        );

        // Insert 2 pending checkpoints.
        for seq in 0..2u64 {
            let checkpoint = NOACheckpointMessage {
                epoch: 1,
                sequence_number: seq,
                messages: vec![],
            };
            let tx = format!("tx_{seq}").into_bytes();
            store.insert_pending(seq, checkpoint, vec![(tx, vec![])]);
        }

        let handle = tokio::spawn(certifier.run());

        // Sign both.
        for seq in 0..2u64 {
            let tx = format!("tx_{seq}").into_bytes();
            output_tx
                .send(NetworkOwnedAddressSignOutput {
                    session_identifier: test_session_id(),
                    message: tx,
                    signature: format!("sig_{seq}").into_bytes(),
                    curve: DWalletCurve::Curve25519,
                    signature_algorithm: DWalletSignatureAlgorithm::EdDSA,
                    hash_scheme: DWalletHashScheme::SHA512,
                })
                .await
                .unwrap();
        }

        // Let certifier process.
        tokio::task::yield_now().await;
        // Small sleep to ensure async processing completes.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        drop(output_tx);
        handle.await.unwrap();

        let results = collected.lock();
        assert_eq!(results.len(), 2, "output handler should be called twice");
        assert_eq!(results[0].checkpoint.sequence_number, 0);
        assert_eq!(results[1].checkpoint.sequence_number, 1);
    }

    #[tokio::test]
    async fn test_submitter_channel_backpressure() {
        // Use a very small channel to test that the submitter doesn't lose messages.
        let store = Arc::new(NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new());
        let (sign_tx, mut sign_rx) = mpsc::unbounded_channel::<NetworkOwnedAddressSignRequest>();
        let (msg_tx, msg_rx) =
            mpsc::channel::<(Vec<DWalletCheckpointMessageKind>, SuiChainContext)>(1);

        let submitter = NOACheckpointSubmitter::<noa_checkpoint::DWallet>::new(
            msg_rx,
            sign_tx,
            store.clone(),
            1,
            vec![],
        );
        let handle = tokio::spawn(submitter.run());

        // Send messages one at a time (channel capacity is 1).
        let ctx = test_sui_chain_context();
        let count = 10;
        for _ in 0..count {
            msg_tx.send((vec![], ctx.clone())).await.unwrap();
        }
        drop(msg_tx);
        handle.await.unwrap();

        let mut received = 0;
        while sign_rx.try_recv().is_ok() {
            received += 1;
        }
        assert_eq!(received, count, "all messages should be processed");
    }

    // =========================================================================
    // Finalization tracking tests
    // =========================================================================

    #[test]
    fn test_finalization_tracking() {
        use ika_types::noa_checkpoint::{NOACheckpointTxRef, NOACheckpointTxStatus};

        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();
        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(b"tx".to_vec(), vec![])]);

        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::DWallet,
            sequence_number: 0,
            tx_index: 0,
            epoch: 1,
        };

        // Initially no finalization entries.
        assert!(store.has_no_finalization_entries());
        assert!(store.get_status(&tx_ref).is_none());

        // Mark submitted.
        store.mark_submitted(tx_ref.clone(), b"chain_tx_id_0".to_vec());
        assert!(!store.has_no_finalization_entries());
        assert_eq!(
            store.get_status(&tx_ref),
            Some(NOACheckpointTxStatus::Pending)
        );
        assert!(!store.all_finalized());

        // Check chain tx id.
        assert_eq!(
            store.get_chain_tx_id(&tx_ref),
            Some(b"chain_tx_id_0".to_vec())
        );

        // Get pending refs — should return the one tx_ref.
        let pending = store.get_pending_refs();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], tx_ref);

        // Mark confirmed locally.
        store.mark_confirmed_locally(&tx_ref);
        assert_eq!(
            store.get_status(&tx_ref),
            Some(NOACheckpointTxStatus::ConfirmedLocally)
        );
        assert!(!store.all_finalized());

        // Mark finalized.
        store.mark_finalized(&tx_ref);
        assert_eq!(
            store.get_status(&tx_ref),
            Some(NOACheckpointTxStatus::Finalized)
        );
        assert!(store.all_finalized());
        assert!(store.get_pending_refs().is_empty());
    }

    #[test]
    fn test_all_finalized_multiple_txs() {
        use ika_types::noa_checkpoint::NOACheckpointTxRef;

        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();

        // Insert a checkpoint with multi-tx (we need the entry to exist).
        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(
            0,
            checkpoint,
            vec![(b"tx_0".to_vec(), vec![]), (b"tx_1".to_vec(), vec![])],
        );

        let first_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::DWallet,
            sequence_number: 0,
            tx_index: 0,
            epoch: 1,
        };
        let second_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::DWallet,
            sequence_number: 0,
            tx_index: 1,
            epoch: 1,
        };

        store.mark_submitted(first_ref.clone(), b"id_0".to_vec());
        store.mark_submitted(second_ref.clone(), b"id_1".to_vec());

        // Only one finalized — should return false.
        store.mark_finalized(&first_ref);
        assert!(!store.all_finalized());

        // Both finalized — should return true.
        store.mark_finalized(&second_ref);
        assert!(store.all_finalized());
    }

    #[test]
    fn test_epoch_change_blocked_until_finalized() {
        use ika_types::noa_checkpoint::NOACheckpointTxRef;

        let store = NOACheckpointLocalStore::<noa_checkpoint::System>::new();

        // No entries = no finalization entries, should not block.
        assert!(store.has_no_finalization_entries());
        let can_advance = store.has_no_finalization_entries() || store.all_finalized();
        assert!(can_advance);

        // Add a pending checkpoint — should block.
        let checkpoint = NOACheckpointMessage {
            epoch: 5,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(b"tx".to_vec(), vec![])]);

        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::System,
            sequence_number: 0,
            tx_index: 0,
            epoch: 5,
        };
        store.mark_submitted(tx_ref.clone(), b"id".to_vec());
        let can_advance = store.has_no_finalization_entries() || store.all_finalized();
        assert!(!can_advance);

        // Finalize — should unblock.
        store.mark_finalized(&tx_ref);
        let can_advance = store.has_no_finalization_entries() || store.all_finalized();
        assert!(can_advance);
    }

    #[test]
    fn test_finalization_mark_unknown_ref_is_noop() {
        use ika_types::noa_checkpoint::NOACheckpointTxRef;

        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();

        let unknown_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::DWallet,
            sequence_number: 99,
            tx_index: 0,
            epoch: 1,
        };

        // These should be no-ops, not panic.
        store.mark_confirmed_locally(&unknown_ref);
        store.mark_finalized(&unknown_ref);
        assert!(store.get_status(&unknown_ref).is_none());
    }

    // =========================================================================
    // Retry / failure voting tests
    // =========================================================================

    #[test]
    fn test_retry_pending_status() {
        use ika_types::noa_checkpoint::{NOACheckpointTxRef, NOACheckpointTxStatus};

        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();
        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(b"tx".to_vec(), vec![])]);

        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::DWallet,
            sequence_number: 0,
            tx_index: 0,
            epoch: 1,
        };

        // Submit and verify Pending.
        store.mark_submitted(tx_ref.clone(), b"chain_id_0".to_vec());
        assert_eq!(
            store.get_status(&tx_ref),
            Some(NOACheckpointTxStatus::Pending)
        );
        assert_eq!(store.get_chain_tx_id(&tx_ref), Some(b"chain_id_0".to_vec()));

        // initiate_tx_retry transitions to RetryPending and clears chain_tx_id/signature.
        let tx_bytes = store.initiate_tx_retry(&tx_ref, &test_sui_chain_context(), &[]);
        assert!(tx_bytes.is_some());
        // Regenerated bytes differ from original (retry_round=1 embedded).
        assert!(!tx_bytes.as_ref().unwrap().is_empty());
        assert_ne!(tx_bytes.unwrap(), b"tx".to_vec());
        assert_eq!(
            store.get_status(&tx_ref),
            Some(NOACheckpointTxStatus::RetryPending)
        );
        assert!(store.get_chain_tx_id(&tx_ref).is_none());
        assert!(!store.has_signature(&tx_ref));

        // RetryPending is not finalized.
        assert!(!store.all_finalized());

        // get_pending_refs includes RetryPending entries.
        let pending = store.get_pending_refs();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], tx_ref);

        // Can finalize from RetryPending.
        store.mark_finalized(&tx_ref);
        assert_eq!(
            store.get_status(&tx_ref),
            Some(NOACheckpointTxStatus::Finalized)
        );
        assert!(store.all_finalized());
    }

    #[test]
    fn test_check_tx_status_tri_state() {
        use crate::noa_checkpoints::{LogOnlyChainSubmitter, NOAChainSubmitter, TxExecutionStatus};

        let submitter = LogOnlyChainSubmitter;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let status = rt.block_on(async {
            <LogOnlyChainSubmitter as NOAChainSubmitter<noa_checkpoint::DWallet>>::check_tx_status(
                &submitter, b"any",
            )
            .await
            .unwrap()
        });
        assert!(matches!(status, TxExecutionStatus::Executed));
    }

    #[test]
    fn test_composite_output() {
        use crate::noa_checkpoints::checkpoint_output::{
            CertifiedNOACheckpointOutput, CompositeOutput,
        };
        use ika_types::noa_checkpoint::CertifiedNOACheckpointMessage;

        let first_collected = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let second_collected = Arc::new(parking_lot::Mutex::new(Vec::new()));

        let first = CollectingOutput::<noa_checkpoint::DWallet> {
            collected: first_collected.clone(),
        };
        let second = CollectingOutput::<noa_checkpoint::DWallet> {
            collected: second_collected.clone(),
        };

        let composite = CompositeOutput::new(vec![Box::new(first), Box::new(second)]);

        let checkpoint = CertifiedNOACheckpointMessage {
            checkpoint: NOACheckpointMessage {
                epoch: 1,
                sequence_number: 0,
                messages: vec![],
            },
            signatures: vec![b"sig".to_vec()],
            signed_bytes: vec![b"tx".to_vec()],
            curve: DWalletCurve::Curve25519,
            signature_algorithm: DWalletSignatureAlgorithm::EdDSA,
        };

        composite.certified_checkpoint_created(&checkpoint).unwrap();

        assert_eq!(first_collected.lock().len(), 1);
        assert_eq!(second_collected.lock().len(), 1);
        assert_eq!(first_collected.lock()[0].checkpoint.sequence_number, 0);
    }

    #[tokio::test]
    async fn test_notify_finalizer_output() {
        use crate::noa_checkpoints::checkpoint_output::{
            CertifiedNOACheckpointOutput, NotifyFinalizerOutput,
        };
        use ika_types::noa_checkpoint::CertifiedNOACheckpointMessage;

        let (tx, mut rx) = mpsc::channel::<u64>(16);
        let output = NotifyFinalizerOutput::new(tx);

        let checkpoint = CertifiedNOACheckpointMessage {
            checkpoint: NOACheckpointMessage::<noa_checkpoint::DWallet> {
                epoch: 1,
                sequence_number: 42,
                messages: vec![],
            },
            signatures: vec![b"sig".to_vec()],
            signed_bytes: vec![b"tx".to_vec()],
            curve: DWalletCurve::Curve25519,
            signature_algorithm: DWalletSignatureAlgorithm::EdDSA,
        };

        output.certified_checkpoint_created(&checkpoint).unwrap();

        let seq = rx.try_recv().expect("should receive seq number");
        assert_eq!(seq, 42);
    }

    #[test]
    fn test_initiate_retry_reregisters_pending() {
        use ika_types::noa_checkpoint::{NOACheckpointTxRef, NOACheckpointTxStatus};

        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();

        // Insert a checkpoint and certify it.
        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        let tx_data = vec![(b"tx_data".to_vec(), vec![])];
        store.insert_pending(0, checkpoint, tx_data);

        store
            .add_signature(
                b"tx_data",
                b"sig".to_vec(),
                DWalletCurve::Curve25519,
                DWalletSignatureAlgorithm::EdDSA,
            )
            .unwrap();

        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::DWallet,
            sequence_number: 0,
            tx_index: 0,
            epoch: 1,
        };

        // Submit, then initiate per-tx retry.
        store.mark_submitted(tx_ref.clone(), b"chain_id".to_vec());
        let retry_bytes = store.initiate_tx_retry(&tx_ref, &test_sui_chain_context(), &[]);
        assert!(retry_bytes.is_some());
        let retry_bytes = retry_bytes.unwrap();
        // Regenerated bytes differ from original (retry_round=1 embedded).
        assert_ne!(retry_bytes, b"tx_data".to_vec());
        assert_eq!(
            store.get_status(&tx_ref),
            Some(NOACheckpointTxStatus::RetryPending)
        );

        // Retry signature can be routed and stored (certified already exists, returns None).
        let recertified = store.add_signature(
            &retry_bytes,
            b"new_sig".to_vec(),
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        assert!(recertified.is_none(), "retry should not rebuild certified");

        // But the signature is stored and retrievable.
        assert!(store.has_signature(&tx_ref));
        let (bytes, sig) = store.get_tx_for_submission(&tx_ref).unwrap();
        assert_eq!(bytes, retry_bytes);
        assert_eq!(sig, b"new_sig".to_vec());
    }

    // =========================================================================
    // Consolidated store: retry_round and voted_failed persistence tests
    // =========================================================================

    #[test]
    fn test_retry_round_persisted_in_store() {
        use ika_types::noa_checkpoint::NOACheckpointTxRef;

        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();

        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(b"tx".to_vec(), vec![])]);

        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::DWallet,
            sequence_number: 0,
            tx_index: 0,
            epoch: 1,
        };

        // Initial retry_round is 0.
        assert_eq!(store.get_retry_round(&tx_ref), 0);

        // Certify.
        store.add_signature(
            b"tx",
            b"sig".to_vec(),
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );

        // Submit and set voted_failed.
        store.mark_submitted(tx_ref.clone(), b"chain_id".to_vec());
        assert!(!store.has_voted_failed(&tx_ref));
        store.set_voted_failed(&tx_ref);
        assert!(store.has_voted_failed(&tx_ref));

        // Simulate retry via initiate_tx_retry.
        store.initiate_tx_retry(&tx_ref, &test_sui_chain_context(), &[]);

        // retry_round should be incremented.
        assert_eq!(store.get_retry_round(&tx_ref), 1);
        // voted_failed should be cleared by initiate_tx_retry.
        assert!(!store.has_voted_failed(&tx_ref));
    }

    #[test]
    fn test_partial_finalization_retry() {
        use ika_types::noa_checkpoint::{NOACheckpointTxRef, NOACheckpointTxStatus};

        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();

        // 3-tx checkpoint.
        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(
            0,
            checkpoint,
            vec![
                (b"tx_0".to_vec(), vec![]),
                (b"tx_1".to_vec(), vec![]),
                (b"tx_2".to_vec(), vec![]),
            ],
        );

        // Sign all 3.
        store.add_signature(
            b"tx_0",
            b"sig_0".to_vec(),
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        store.add_signature(
            b"tx_1",
            b"sig_1".to_vec(),
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        store
            .add_signature(
                b"tx_2",
                b"sig_2".to_vec(),
                DWalletCurve::Curve25519,
                DWalletSignatureAlgorithm::EdDSA,
            )
            .expect("should certify");

        let make_ref = |idx: u32| NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::DWallet,
            sequence_number: 0,
            tx_index: idx,
            epoch: 1,
        };

        // Submit all 3.
        store.mark_submitted(make_ref(0), b"id_0".to_vec());
        store.mark_submitted(make_ref(1), b"id_1".to_vec());
        store.mark_submitted(make_ref(2), b"id_2".to_vec());

        // Finalize tx_0 only.
        store.mark_finalized(&make_ref(0));
        assert_eq!(
            store.get_status(&make_ref(0)),
            Some(NOACheckpointTxStatus::Finalized)
        );

        // Retry tx_1 and tx_2 (simulating failure quorum on those).
        store.initiate_tx_retry(&make_ref(1), &test_sui_chain_context(), &[]);
        store.initiate_tx_retry(&make_ref(2), &test_sui_chain_context(), &[]);

        // tx_0 must remain Finalized — not affected by retry of siblings.
        assert_eq!(
            store.get_status(&make_ref(0)),
            Some(NOACheckpointTxStatus::Finalized)
        );
        assert_eq!(store.get_retry_round(&make_ref(0)), 0);

        // tx_1 and tx_2 are RetryPending with retry_round 1.
        assert_eq!(
            store.get_status(&make_ref(1)),
            Some(NOACheckpointTxStatus::RetryPending)
        );
        assert_eq!(
            store.get_status(&make_ref(2)),
            Some(NOACheckpointTxStatus::RetryPending)
        );
        assert_eq!(store.get_retry_round(&make_ref(1)), 1);
        assert_eq!(store.get_retry_round(&make_ref(2)), 1);

        // all_finalized should be false (tx_1 and tx_2 not finalized).
        assert!(!store.all_finalized());

        // get_pending_refs should return tx_1 and tx_2 only.
        let pending = store.get_pending_refs();
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().all(|r| r.tx_index == 1 || r.tx_index == 2));
    }

    #[test]
    fn test_confirmed_locally_skips_failure_quorum_check() {
        // This is a design test: once a tx is ConfirmedLocally, the poll_loop
        // should NOT check failure quorum. We verify by checking that
        // ConfirmedLocally status is distinct from Pending.
        use ika_types::noa_checkpoint::{NOACheckpointTxRef, NOACheckpointTxStatus};

        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();
        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(b"tx".to_vec(), vec![])]);

        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::DWallet,
            sequence_number: 0,
            tx_index: 0,
            epoch: 1,
        };

        store.mark_submitted(tx_ref.clone(), b"chain_id".to_vec());
        store.mark_confirmed_locally(&tx_ref);

        // Status is ConfirmedLocally, not Pending — failure quorum check is only
        // in the Pending arm of poll_loop's match, so it won't fire.
        assert_eq!(
            store.get_status(&tx_ref),
            Some(NOACheckpointTxStatus::ConfirmedLocally)
        );

        // ConfirmedLocally is still not finalized.
        assert!(!store.all_finalized());

        // get_pending_refs returns ConfirmedLocally entries (they're not Finalized).
        let pending = store.get_pending_refs();
        assert_eq!(pending.len(), 1);
    }

    // =========================================================================
    // Per-tx byte regeneration tests
    // =========================================================================

    #[test]
    fn test_retry_regenerates_bytes() {
        use ika_types::noa_checkpoint::NOACheckpointTxRef;

        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();
        let ctx = test_sui_chain_context();

        // Build initial tx_bytes via build_tx_bytes so we have a realistic baseline.
        let initial_bytes = noa_checkpoint::DWallet::build_tx_bytes(1, 0, 0, &[], &ctx, &[], 0);
        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(initial_bytes.clone(), vec![])]);

        // Certify.
        store
            .add_signature(
                &initial_bytes,
                b"sig".to_vec(),
                DWalletCurve::Curve25519,
                DWalletSignatureAlgorithm::EdDSA,
            )
            .expect("should certify");

        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::DWallet,
            sequence_number: 0,
            tx_index: 0,
            epoch: 1,
        };

        // Submit and retry.
        store.mark_submitted(tx_ref.clone(), b"chain_id".to_vec());
        let retry_bytes = store
            .initiate_tx_retry(&tx_ref, &ctx, &[])
            .expect("retry should succeed");

        // Regenerated bytes differ from original (retry_round=1).
        assert_ne!(retry_bytes, initial_bytes);

        // Old bytes removed from tx_to_seq, new bytes registered.
        assert!(
            store
                .add_signature(
                    &initial_bytes,
                    b"stale_sig".to_vec(),
                    DWalletCurve::Curve25519,
                    DWalletSignatureAlgorithm::EdDSA,
                )
                .is_none(),
            "old bytes should not route"
        );

        // New bytes can receive a signature.
        store.add_signature(
            &retry_bytes,
            b"retry_sig".to_vec(),
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        assert!(store.has_signature(&tx_ref));

        // get_tx_for_submission returns the new bytes.
        let (bytes, sig) = store.get_tx_for_submission(&tx_ref).unwrap();
        assert_eq!(bytes, retry_bytes);
        assert_eq!(sig, b"retry_sig".to_vec());
    }

    #[test]
    fn test_retry_with_different_context() {
        use ika_types::noa_checkpoint::NOACheckpointTxRef;

        let store = NOACheckpointLocalStore::<noa_checkpoint::DWallet>::new();
        let initial_ctx = test_sui_chain_context();

        let initial_bytes =
            noa_checkpoint::DWallet::build_tx_bytes(1, 0, 0, &[], &initial_ctx, &[], 0);
        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(initial_bytes.clone(), vec![])]);

        store
            .add_signature(
                &initial_bytes,
                b"sig".to_vec(),
                DWalletCurve::Curve25519,
                DWalletSignatureAlgorithm::EdDSA,
            )
            .expect("should certify");

        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::DWallet,
            sequence_number: 0,
            tx_index: 0,
            epoch: 1,
        };

        store.mark_submitted(tx_ref.clone(), b"chain_id".to_vec());

        // Retry with a different context (e.g., new Sui epoch).
        let new_ctx = SuiChainContext {
            reference_gas_price: 2000,
            sui_epoch: 2,
        };
        let retry_bytes = store
            .initiate_tx_retry(&tx_ref, &new_ctx, &[])
            .expect("retry should succeed");

        // Bytes differ from both original and what same-context retry would produce.
        assert_ne!(retry_bytes, initial_bytes);

        // Signature routes correctly via add_signature with new bytes.
        store.add_signature(
            &retry_bytes,
            b"retry_sig".to_vec(),
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
        );
        assert!(store.has_signature(&tx_ref));
        let (bytes, _) = store.get_tx_for_submission(&tx_ref).unwrap();
        assert_eq!(bytes, retry_bytes);
    }
}
