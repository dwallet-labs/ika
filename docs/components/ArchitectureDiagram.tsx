'use client';

import { clsx } from 'clsx';
import React from 'react';

// ============================================================================
// TYPES
// ============================================================================

export interface DiagramNode {
	id: string;
	label: string;
	subtitle?: string;
	children?: DiagramNode[];
	variant?: 'primary' | 'secondary' | 'accent' | 'muted';
}

export interface DiagramLayer {
	id: string;
	title: string;
	subtitle?: string;
	nodes?: DiagramNode[];
	variant?: 'primary' | 'secondary' | 'accent';
}

export interface ArchitectureDiagramProps {
	title?: string;
	layers: DiagramLayer[];
	showArrows?: boolean;
	className?: string;
}

// ============================================================================
// SUB-COMPONENTS
// ============================================================================

function ConnectorArrows({ count = 1 }: { count?: number }) {
	return (
		<div className="flex justify-center items-center gap-16 py-2">
			{Array.from({ length: Math.min(count, 3) }).map((_, i) => (
				<div key={i} className="flex flex-col items-center">
					<div className="w-px h-5 bg-ika-400/50" />
					<div className="text-ika-400 text-sm">▼</div>
				</div>
			))}
		</div>
	);
}

function NodeBox({ node, isNested = false }: { node: DiagramNode; isNested?: boolean }) {
	const variants = {
		primary: 'border-ika-400/50 bg-ika-500/10',
		secondary: 'border-slate-600/50 bg-slate-800/30',
		accent: 'border-ika-500/60 bg-ika-500/15',
		muted: 'border-slate-700/50 bg-slate-900/30',
	};

	const variant = node.variant || (isNested ? 'muted' : 'secondary');

	return (
		<div
			className={clsx('border rounded-md px-3 py-2 text-center min-w-[100px]', variants[variant])}
		>
			<div className={clsx('font-medium text-slate-200', isNested ? 'text-xs' : 'text-sm')}>
				{node.label}
			</div>
			{node.subtitle && <div className="text-[11px] text-slate-400 mt-0.5">{node.subtitle}</div>}
			{node.children && node.children.length > 0 && (
				<div className="flex flex-wrap gap-2 mt-2 justify-center">
					{node.children.map((child) => (
						<NodeBox key={child.id} node={child} isNested />
					))}
				</div>
			)}
		</div>
	);
}

function LayerBox({ layer }: { layer: DiagramLayer }) {
	const variants = {
		primary: 'border-ika-400/40',
		secondary: 'border-slate-700/60',
		accent: 'border-ika-500/50',
	};

	return (
		<div
			className={clsx(
				'border rounded-lg p-4 bg-slate-900/50',
				variants[layer.variant || 'primary'],
			)}
		>
			<div className="text-center mb-3">
				<div className="text-sm font-semibold text-ika-400">{layer.title}</div>
				{layer.subtitle && <div className="text-xs text-slate-500 mt-0.5">{layer.subtitle}</div>}
			</div>
			{layer.nodes && layer.nodes.length > 0 && (
				<div className="flex flex-wrap gap-3 justify-center">
					{layer.nodes.map((node) => (
						<NodeBox key={node.id} node={node} />
					))}
				</div>
			)}
		</div>
	);
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function ArchitectureDiagram({
	title,
	layers,
	showArrows = true,
	className,
}: ArchitectureDiagramProps) {
	return (
		<div className={clsx('my-6', className)}>
			{title && <h3 className="text-base font-semibold text-ika-400 mb-4 italic">{title}</h3>}
			<div className="rounded-xl bg-[#0a0a0a] border border-slate-800/50 p-5">
				<div className="space-y-0">
					{layers.map((layer, index) => (
						<React.Fragment key={layer.id}>
							<LayerBox layer={layer} />
							{showArrows && index < layers.length - 1 && (
								<ConnectorArrows count={layer.nodes?.length || 1} />
							)}
						</React.Fragment>
					))}
				</div>
			</div>
		</div>
	);
}

// ============================================================================
// PRESET DIAGRAMS
// ============================================================================

export function ArchitectureOverviewDiagram() {
	return (
		<ArchitectureDiagram
			title="Architecture Overview"
			layers={[
				{
					id: 'contract',
					title: 'Your Move Contract',
					variant: 'primary',
					nodes: [
						{ id: 'cap', label: 'DWalletCap', subtitle: '(stored)', variant: 'accent' },
						{ id: 'presigns', label: 'Presigns', subtitle: '(pooled)', variant: 'secondary' },
						{
							id: 'logic',
							label: 'Business Logic',
							subtitle: '(governance, approvals)',
							variant: 'secondary',
						},
					],
				},
				{
					id: 'coordinator',
					title: 'DWalletCoordinator',
					variant: 'accent',
					nodes: [
						{ id: 'dkg', label: 'DKG', subtitle: 'Protocol', variant: 'muted' },
						{ id: 'presign', label: 'Presign', subtitle: 'Protocol', variant: 'muted' },
						{ id: 'sign', label: 'Sign', subtitle: 'Protocol', variant: 'muted' },
						{ id: 'future', label: 'Future Sign', subtitle: 'Protocol', variant: 'muted' },
					],
				},
				{
					id: 'network',
					title: 'Ika Network',
					subtitle: '(2PC-MPC Protocol Execution)',
					variant: 'secondary',
				},
			]}
		/>
	);
}

export function ProtocolLifecycleDiagram() {
	return (
		<ArchitectureDiagram
			title="Protocol Lifecycle"
			layers={[
				{
					id: 'dkg',
					title: 'DKG',
					subtitle: 'Create dWallet and receive DWalletCap',
					variant: 'primary',
					nodes: [
						{ id: 'cap', label: 'DWalletCap', subtitle: '(store permanently)', variant: 'accent' },
					],
				},
				{
					id: 'presign',
					title: 'PRESIGN',
					subtitle: 'Pre-compute cryptographic material for signing',
					variant: 'accent',
					nodes: [
						{
							id: 'unverified',
							label: 'UnverifiedPresignCap',
							subtitle: '(store in pool)',
							variant: 'secondary',
						},
						{
							id: 'verified',
							label: 'VerifiedPresignCap',
							subtitle: '(ready to use)',
							variant: 'primary',
						},
					],
				},
				{
					id: 'signing',
					title: 'Signing Options',
					variant: 'secondary',
					nodes: [
						{
							id: 'direct',
							label: 'SIGN',
							subtitle: '(Direct signing)',
							variant: 'primary',
							children: [
								{ id: 's1', label: 'approve_message()', variant: 'muted' },
								{ id: 's2', label: 'request_sign()', variant: 'muted' },
							],
						},
						{
							id: 'future',
							label: 'FUTURE SIGN',
							subtitle: '(Two-phase signing)',
							variant: 'accent',
							children: [
								{ id: 'f1', label: 'Phase 1: Commit', variant: 'muted' },
								{ id: 'f2', label: 'Phase 2: Execute', variant: 'muted' },
							],
						},
					],
				},
			]}
		/>
	);
}

export function PresignLifecycleDiagram() {
	return (
		<ArchitectureDiagram
			title="Presign Lifecycle"
			layers={[
				{
					id: 'request',
					title: '1. REQUEST',
					subtitle: 'request_global_presign() or request_presign()',
					variant: 'primary',
					nodes: [
						{
							id: 'unverified',
							label: 'UnverifiedPresignCap',
							subtitle: '(store in pool)',
							variant: 'accent',
						},
					],
				},
				{
					id: 'verify',
					title: '2. VERIFY',
					subtitle: 'Network processes presign (async)',
					variant: 'accent',
					nodes: [
						{
							id: 'verified',
							label: 'VerifiedPresignCap',
							subtitle: '(ready for signing)',
							variant: 'primary',
						},
					],
				},
				{
					id: 'consume',
					title: '3. CONSUME',
					subtitle: 'Presign is destroyed during signing',
					variant: 'secondary',
				},
			]}
		/>
	);
}

export function KeyImportDiagram() {
	return (
		<ArchitectureDiagram
			title="Import Process"
			layers={[
				{
					id: 'prepare',
					title: '1. PREPARE (TypeScript SDK)',
					subtitle: 'prepareImportedKeyDWalletVerification()',
					variant: 'primary',
					nodes: [
						{ id: 'output', label: 'userPublicOutput', variant: 'muted' },
						{
							id: 'message',
							label: 'userMessage',
							subtitle: '(centralized party)',
							variant: 'muted',
						},
						{ id: 'proof', label: 'encryptedUserShareAndProof', variant: 'muted' },
					],
				},
				{
					id: 'request',
					title: '2. REQUEST VERIFICATION (Move)',
					subtitle: 'coordinator.request_imported_key_dwallet_verification()',
					variant: 'accent',
					nodes: [{ id: 'cap', label: 'ImportedKeyDWalletCap', variant: 'primary' }],
				},
				{
					id: 'ready',
					title: '3. READY TO SIGN',
					subtitle: 'Network verifies import',
					variant: 'secondary',
					nodes: [
						{ id: 'approve', label: 'approve_imported_key_message()', variant: 'muted' },
						{ id: 'sign', label: 'request_imported_key_sign()', variant: 'muted' },
					],
				},
			]}
		/>
	);
}

export function FutureSigningDiagram() {
	return (
		<ArchitectureDiagram
			title="Two-Phase Process"
			layers={[
				{
					id: 'phase1',
					title: 'PHASE 1: COMMIT',
					subtitle: 'User creates partial signature and stores it',
					variant: 'primary',
					nodes: [
						{ id: 'request', label: 'request_future_sign()', variant: 'accent' },
						{
							id: 'cap',
							label: 'UnverifiedPartialUserSignatureCap',
							subtitle: '(store with request)',
							variant: 'secondary',
						},
					],
				},
				{
					id: 'governance',
					title: 'Governance / Approval Process',
					subtitle: 'Network verifies partial signature',
					variant: 'secondary',
				},
				{
					id: 'phase2',
					title: 'PHASE 2: EXECUTE',
					subtitle: 'After approval, complete the signature',
					variant: 'accent',
					nodes: [
						{ id: 'verify', label: 'verify_partial_user_signature_cap()', variant: 'muted' },
						{ id: 'approve', label: 'approve_message()', variant: 'muted' },
						{ id: 'sign', label: 'request_sign_with_partial_user_signature()', variant: 'primary' },
					],
				},
			]}
		/>
	);
}

export function CapabilityLifecycleDiagram() {
	return (
		<ArchitectureDiagram
			title="Capability Lifecycle Summary"
			showArrows={false}
			layers={[
				{
					id: 'dkg',
					title: 'DKG',
					variant: 'primary',
					nodes: [
						{
							id: 'flow',
							label: 'request_dwallet_dkg() → DWalletCap',
							subtitle: '(store permanently)',
							variant: 'accent',
						},
					],
				},
				{
					id: 'presigning',
					title: 'Presigning',
					variant: 'secondary',
					nodes: [
						{
							id: 'request',
							label: 'request_presign()',
							subtitle: '→ UnverifiedPresignCap (pool)',
							variant: 'muted',
						},
						{
							id: 'verify',
							label: 'verify_presign_cap()',
							subtitle: '→ VerifiedPresignCap (use once)',
							variant: 'muted',
						},
					],
				},
				{
					id: 'signing',
					title: 'Signing',
					variant: 'accent',
					nodes: [
						{
							id: 'approve',
							label: 'approve_message()',
							subtitle: '→ MessageApproval',
							variant: 'muted',
						},
						{ id: 'sign', label: 'request_sign()', subtitle: 'consumes caps', variant: 'primary' },
					],
				},
				{
					id: 'future',
					title: 'Future Signing',
					variant: 'secondary',
					nodes: [
						{
							id: 'future',
							label: 'request_future_sign()',
							subtitle: '→ UnverifiedPartialUserSignatureCap',
							variant: 'muted',
						},
						{
							id: 'complete',
							label: 'request_sign_with_partial...',
							subtitle: 'completes signing',
							variant: 'muted',
						},
					],
				},
			]}
		/>
	);
}

export function SigningFlowDiagram() {
	return (
		<ArchitectureDiagram
			title="Signing Flow"
			layers={[
				{
					id: 'start',
					title: 'Start with Ready Presign',
					variant: 'primary',
					nodes: [
						{
							id: 'presign',
							label: 'VerifiedPresignCap',
							subtitle: '(from pool)',
							variant: 'accent',
						},
					],
				},
				{
					id: 'approve',
					title: 'Approve Message',
					subtitle: 'coordinator.approve_message()',
					variant: 'accent',
					nodes: [{ id: 'approval', label: 'MessageApproval', variant: 'primary' }],
				},
				{
					id: 'sign',
					title: 'Request Signature',
					subtitle: 'coordinator.request_sign()',
					variant: 'secondary',
					nodes: [
						{
							id: 'sig',
							label: 'Signature ID',
							subtitle: '(network creates signature)',
							variant: 'accent',
						},
					],
				},
			]}
		/>
	);
}

export function MultisigFlowDiagram() {
	return (
		<ArchitectureDiagram
			title="Multisig Transaction Flow"
			layers={[
				{
					id: 'create',
					title: '1. Create Request',
					subtitle: 'Member proposes transaction',
					variant: 'primary',
					nodes: [
						{ id: 'partial', label: 'request_future_sign()', variant: 'accent' },
						{
							id: 'store',
							label: 'Store PartialSigCap',
							subtitle: 'with request',
							variant: 'secondary',
						},
					],
				},
				{
					id: 'vote',
					title: '2. Voting',
					subtitle: 'Members approve or reject',
					variant: 'secondary',
					nodes: [
						{ id: 'approve', label: 'Approve', variant: 'accent' },
						{ id: 'reject', label: 'Reject', variant: 'muted' },
					],
				},
				{
					id: 'execute',
					title: '3. Execute',
					subtitle: 'When threshold reached',
					variant: 'accent',
					nodes: [
						{ id: 'complete', label: 'Complete Signature', variant: 'primary' },
						{ id: 'broadcast', label: 'Broadcast to Bitcoin', variant: 'secondary' },
					],
				},
			]}
		/>
	);
}

export function SharedDWalletFlowDiagram() {
	return (
		<ArchitectureDiagram
			title="Shared dWallet Flow"
			layers={[
				{
					id: 'create',
					title: 'Create Shared dWallet',
					subtitle: 'DKG with public user share',
					variant: 'primary',
					nodes: [
						{
							id: 'dkg',
							label: 'request_dwallet_dkg_with_public_user_secret_key_share()',
							variant: 'accent',
						},
					],
				},
				{
					id: 'store',
					title: 'Contract Storage',
					variant: 'secondary',
					nodes: [
						{
							id: 'cap',
							label: 'DWalletCap',
							subtitle: '(stored in contract)',
							variant: 'primary',
						},
						{ id: 'presigns', label: 'Presign Pool', variant: 'muted' },
						{ id: 'balance', label: 'Fee Balances', variant: 'muted' },
					],
				},
				{
					id: 'sign',
					title: 'Sign Without User',
					subtitle: 'Contract controls signing',
					variant: 'accent',
					nodes: [
						{
							id: 'logic',
							label: 'Business Logic',
							subtitle: 'defines when to sign',
							variant: 'secondary',
						},
					],
				},
			]}
		/>
	);
}
