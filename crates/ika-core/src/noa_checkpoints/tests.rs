// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Tests for the NOA checkpoint handler:
//! `NOACheckpointLocalStore` unit tests and `NOACheckpointHandler<K>` integration tests.

mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use dwallet_mpc_types::dwallet_mpc::{DWalletCurve, DWalletSignatureAlgorithm};
    use ika_types::messages_dwallet_mpc::{SessionIdentifier, SessionType};
    use ika_types::messages_system_checkpoints::SystemCheckpointMessageKind;
    use ika_types::noa_checkpoint::{
        self, CounterpartyChain, NOACheckpointKind, NOACheckpointKindName, NOACheckpointMessage,
        SuiChainContext,
    };

    use crate::dwallet_mpc::NetworkOwnedAddressSignOutput;
    use crate::noa_checkpoints::{
        LogOnlyChainSubmitter, NOACheckpointHandler, NOACheckpointLocalStore,
    };

    fn test_session_id() -> SessionIdentifier {
        SessionIdentifier::new(SessionType::System, [0u8; SessionIdentifier::LENGTH])
    }

    fn test_sui_chain_context() -> SuiChainContext {
        SuiChainContext {
            reference_gas_price: 1000,
            sui_epoch: 1,
        }
    }

    // =========================================================================
    // NOACheckpointLocalStore unit tests
    // =========================================================================

    #[test]
    fn test_local_store_single_tx_checkpoint() {
        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();

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
        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiSystemCheckpoint>::new();

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
        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();

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
        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();

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
        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();

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
        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();

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
    // NOACheckpointHandler tests
    // =========================================================================

    /// Helper to create a handler for testing.
    fn create_test_handler<K: NOACheckpointKind>() -> NOACheckpointHandler<K> {
        let flag = Arc::new(AtomicBool::new(true));
        NOACheckpointHandler::<K>::new(
            Arc::new(LogOnlyChainSubmitter),
            1, // epoch
            vec![],
            flag,
        )
    }

    #[test]
    fn test_handler_sends_sign_requests() {
        let mut handler = create_test_handler::<noa_checkpoint::SuiDWalletCheckpoint>();

        let ctx = test_sui_chain_context();
        let first_requests = handler.handle_new_checkpoint(vec![], ctx.clone());
        let second_requests = handler.handle_new_checkpoint(vec![], ctx);

        assert_eq!(first_requests.len(), 1, "should have 1 sign request");
        assert_eq!(second_requests.len(), 1, "should have 1 sign request");

        assert_eq!(
            first_requests[0].curve,
            noa_checkpoint::SuiCounterpartyChain::CURVE
        );
        assert_eq!(
            first_requests[0].signature_algorithm,
            noa_checkpoint::SuiCounterpartyChain::SIGNATURE_ALGORITHM
        );
        assert_eq!(
            first_requests[0].hash_scheme,
            noa_checkpoint::SuiCounterpartyChain::HASH_SCHEME
        );

        // Messages should be different (different sequence numbers → different signable bytes).
        assert_ne!(
            first_requests[0].message, second_requests[0].message,
            "different checkpoints should produce different tx bytes"
        );
    }

    #[tokio::test]
    async fn test_handler_certifies_and_submits_to_chain() {
        let mut handler = create_test_handler::<noa_checkpoint::SuiDWalletCheckpoint>();

        // Send a checkpoint.
        let ctx = test_sui_chain_context();
        let requests = handler.handle_new_checkpoint(vec![], ctx);
        assert_eq!(requests.len(), 1);

        let req = &requests[0];

        // Simulate MPC signing.
        handler
            .handle_sign_output(NetworkOwnedAddressSignOutput {
                session_identifier: test_session_id(),
                message: req.message.clone(),
                signature: b"mpc_signature".to_vec(),
                curve: req.curve,
                signature_algorithm: req.signature_algorithm,
                hash_scheme: req.hash_scheme,
            })
            .await;

        // After sign output, the checkpoint should be certified and submitted.
        // With LogOnlyChainSubmitter, it's immediately "executed".
    }

    #[tokio::test]
    async fn test_end_to_end_handler() {
        let mut handler = create_test_handler::<noa_checkpoint::SuiDWalletCheckpoint>();

        // Send 3 checkpoints.
        let ctx = test_sui_chain_context();
        let mut all_requests = Vec::new();
        for _ in 0..3 {
            let requests = handler.handle_new_checkpoint(vec![], ctx.clone());
            all_requests.extend(requests);
        }
        assert_eq!(all_requests.len(), 3, "one sign request per checkpoint");

        for req in &all_requests {
            handler
                .handle_sign_output(NetworkOwnedAddressSignOutput {
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
                .await;
        }
    }

    #[tokio::test]
    async fn test_end_to_end_system_checkpoint_handler() {
        let mut handler = create_test_handler::<noa_checkpoint::SuiSystemCheckpoint>();

        // Send a system checkpoint with a real message.
        let requests = handler.handle_new_checkpoint(
            vec![SystemCheckpointMessageKind::EndOfPublish],
            test_sui_chain_context(),
        );
        assert_eq!(requests.len(), 1);

        let req = &requests[0];
        assert_eq!(req.curve, noa_checkpoint::SuiCounterpartyChain::CURVE);

        handler
            .handle_sign_output(NetworkOwnedAddressSignOutput {
                session_identifier: test_session_id(),
                message: req.message.clone(),
                signature: b"system_sig".to_vec(),
                curve: req.curve,
                signature_algorithm: req.signature_algorithm,
                hash_scheme: req.hash_scheme,
            })
            .await;
    }

    // =========================================================================
    // Finalization tracking tests
    // =========================================================================

    #[test]
    fn test_finalization_tracking() {
        use ika_types::noa_checkpoint::{NOACheckpointTxRef, NOACheckpointTxStatus};

        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();
        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(b"tx".to_vec(), vec![])]);

        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::SuiDWallet,
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

        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();

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
            kind_name: NOACheckpointKindName::SuiDWallet,
            sequence_number: 0,
            tx_index: 0,
            epoch: 1,
        };
        let second_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::SuiDWallet,
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

        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiSystemCheckpoint>::new();

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
            kind_name: NOACheckpointKindName::SuiSystem,
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

        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();

        let unknown_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::SuiDWallet,
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

        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();
        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(b"tx".to_vec(), vec![])]);

        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::SuiDWallet,
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
            <LogOnlyChainSubmitter as NOAChainSubmitter<noa_checkpoint::SuiDWalletCheckpoint>>::check_tx_status(
                &submitter, b"any",
            )
            .await
            .unwrap()
        });
        assert!(matches!(status, TxExecutionStatus::Executed));
    }

    #[test]
    fn test_initiate_retry_reregisters_pending() {
        use ika_types::noa_checkpoint::{NOACheckpointTxRef, NOACheckpointTxStatus};

        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();

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
            kind_name: NOACheckpointKindName::SuiDWallet,
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

        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();

        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(b"tx".to_vec(), vec![])]);

        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::SuiDWallet,
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

        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();

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
            kind_name: NOACheckpointKindName::SuiDWallet,
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
        use ika_types::noa_checkpoint::{NOACheckpointTxRef, NOACheckpointTxStatus};

        let mut store = NOACheckpointLocalStore::<noa_checkpoint::SuiDWalletCheckpoint>::new();
        let checkpoint = NOACheckpointMessage {
            epoch: 1,
            sequence_number: 0,
            messages: vec![],
        };
        store.insert_pending(0, checkpoint, vec![(b"tx".to_vec(), vec![])]);

        let tx_ref = NOACheckpointTxRef {
            kind_name: NOACheckpointKindName::SuiDWallet,
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
    // Handler finalization flag tests
    // =========================================================================

    #[test]
    fn test_handler_updates_finalized_flag() {
        let flag = Arc::new(AtomicBool::new(true));
        let mut handler = NOACheckpointHandler::<noa_checkpoint::SuiDWalletCheckpoint>::new(
            Arc::new(LogOnlyChainSubmitter),
            1,
            vec![],
            flag.clone(),
        );

        // Send a checkpoint — handler will store it but flag should remain true
        // (has_no_finalization_entries is true since no txs submitted to chain yet).
        let _requests = handler.handle_new_checkpoint(vec![], test_sui_chain_context());
        handler.update_finalized_flag();
        assert!(
            flag.load(Ordering::Acquire),
            "flag should be true before any chain submission"
        );
    }
}
