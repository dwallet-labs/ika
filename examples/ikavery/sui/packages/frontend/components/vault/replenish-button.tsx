'use client';

import { Button } from '@fesal-packages/ikavery-frontend-ui';
import { useCurrentAccount, useWalletConnection } from '@mysten/dapp-kit-react';
import { fromBase64 } from '@mysten/sui/utils';
import { useQueryClient } from '@tanstack/react-query';
import { AnimatePresence, motion } from 'framer-motion';
import { AlertCircle, CheckCircle2, Loader2, RefreshCw, Wallet, X } from 'lucide-react';
import * as React from 'react';
import { createPortal } from 'react-dom';

import { WalletConnect } from '@/components/wallet-connect';
import { dAppKit } from '@/lib/dapp-kit';
import { useRecoveryClient } from '@/lib/recovery-client-context';
import { PRESIGN_IKA_PER_CALL, PRESIGN_SUI_PER_CALL, replenishPresigns } from '@/lib/replenish';
import { simulateOrThrow } from '@/lib/sponsored-sign';

interface ReplenishButtonProps {
	recoveryId: string;
	/** Suggested fill — typically max(2, bundle.txCount + 1). */
	suggestedCount?: number;
	/** Compact variant: just a tiny inline button. */
	compact?: boolean;
	className?: string;
}

export function ReplenishButton({
	recoveryId,
	suggestedCount = 5,
	compact = false,
	className,
}: ReplenishButtonProps) {
	const queryClient = useQueryClient();
	const account = useCurrentAccount();
	const { isConnecting: walletReconnecting } = useWalletConnection();
	const { suiClient } = useRecoveryClient();
	const walletSign = dAppKit.signTransaction;

	const [open, setOpen] = React.useState(false);
	const [mounted, setMounted] = React.useState(false);
	const [count, setCount] = React.useState(Math.max(1, suggestedCount));

	React.useEffect(() => {
		setMounted(true);
	}, []);
	const [submitting, setSubmitting] = React.useState(false);
	const [error, setError] = React.useState<string | null>(null);
	const [done, setDone] = React.useState<{
		count: number;
		digest: string;
	} | null>(null);

	React.useEffect(() => {
		setCount(Math.max(1, suggestedCount));
	}, [suggestedCount]);

	// Lock body scroll while the modal is open.
	React.useEffect(() => {
		if (!open) return;
		const prev = document.body.style.overflow;
		document.body.style.overflow = 'hidden';
		return () => {
			document.body.style.overflow = prev;
		};
	}, [open]);

	// Close on Escape, but only when not mid-submit (don't drop a pending tx).
	const closeAndReset = React.useCallback(() => {
		setOpen(false);
		setError(null);
		setDone(null);
	}, []);

	React.useEffect(() => {
		if (!open) return;
		const onKey = (e: KeyboardEvent) => {
			if (e.key === 'Escape' && !submitting) closeAndReset();
		};
		window.addEventListener('keydown', onKey);
		return () => window.removeEventListener('keydown', onKey);
	}, [open, submitting, closeAndReset]);

	async function handleSubmit() {
		if (!suiClient || !account) return;
		setSubmitting(true);
		setError(null);
		setDone(null);
		try {
			const res = await replenishPresigns({
				recoveryId,
				count,
				payerAddress: account.address,
				suiClient,
				signAndExecute: async (transaction) => {
					await simulateOrThrow(suiClient, transaction);
					const { bytes, signature } = await walletSign({ transaction });
					return await suiClient.core.executeTransaction({
						transaction: fromBase64(bytes),
						signatures: [signature],
						include: { events: true, effects: true, objectTypes: true },
					});
				},
			});
			setDone({ count: res.count, digest: res.digest });
			await queryClient.invalidateQueries({
				queryKey: ['vault', recoveryId],
			});
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			setError(msg);
		} finally {
			setSubmitting(false);
		}
	}

	const totalIka = PRESIGN_IKA_PER_CALL * BigInt(count);
	const totalSui = PRESIGN_SUI_PER_CALL * BigInt(count);

	return (
		<>
			<Button
				variant={compact ? 'ghost' : 'secondary'}
				size={compact ? 'sm' : 'default'}
				onClick={() => {
					setOpen(true);
					setError(null);
					setDone(null);
				}}
				className={className}
			>
				<RefreshCw className="h-3.5 w-3.5" />
				Replenish presigns
			</Button>

			{mounted &&
				createPortal(
					<AnimatePresence>
						{open && (
							<motion.div
								key="replenish-overlay"
								className="fixed inset-0 z-[110] flex items-center justify-center px-4 py-6"
								initial={{ opacity: 0 }}
								animate={{ opacity: 1 }}
								exit={{ opacity: 0 }}
								transition={{ duration: 0.25 }}
								aria-modal="true"
								role="dialog"
								aria-labelledby="replenish-title"
							>
								<button
									type="button"
									aria-label="Close"
									onClick={() => !submitting && closeAndReset()}
									disabled={submitting}
									className="absolute inset-0 backdrop-blur-md disabled:cursor-not-allowed"
									style={{ background: 'rgba(15, 17, 20, 0.72)' }}
								/>

								<motion.div
									initial={{ opacity: 0, y: 16, scale: 0.98 }}
									animate={{ opacity: 1, y: 0, scale: 1 }}
									exit={{ opacity: 0, y: 8, scale: 0.98 }}
									transition={{ duration: 0.32, ease: [0.22, 1, 0.36, 1] }}
									className="relative surface-raised w-full max-w-[480px]"
								>
									<div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-clay to-transparent" />

									<button
										type="button"
										onClick={closeAndReset}
										disabled={submitting}
										className="absolute top-3 right-3 z-10 h-7 w-7 inline-flex items-center justify-center rounded-md border border-border text-text-3 hover:text-text hover:border-border-strong disabled:opacity-30 disabled:cursor-not-allowed"
										aria-label="Close"
									>
										<X className="h-3.5 w-3.5" />
									</button>

									<div className="px-5 sm:px-7 pt-6 pb-3 pr-12 flex items-start gap-3">
										<span className="h-9 w-9 flex-none flex items-center justify-center rounded-md border border-clay/40 bg-clay/10">
											<RefreshCw className="h-4 w-4 text-clay" strokeWidth={1.7} />
										</span>
										<div className="flex-1 min-w-0">
											<div className="smallcaps text-clay">Vault maintenance</div>
											<h2
												id="replenish-title"
												className="font-display text-[22px] sm:text-[26px] leading-[1.1] tracking-[-0.01em] text-text mt-1"
											>
												Replenish presigns
											</h2>
										</div>
									</div>

									<div className="px-5 sm:px-7 pb-3">
										<p className="text-[13px] text-text-2 leading-[1.55]">
											Each presign warms a signing slot — every Solana tx in a sweep consumes one.
											Replenishing is permissionless; the connected wallet pays.
										</p>
									</div>

									{done ? (
										<div className="px-5 sm:px-7 pb-6 sm:pb-7">
											<div className="flex items-start gap-2 text-[13px] text-text-2 leading-[1.55]">
												<CheckCircle2 className="h-3.5 w-3.5 text-sage mt-0.5 flex-none" />
												<div>
													Requested <span className="text-text">{done.count}</span> new presign
													{done.count === 1 ? '' : 's'}. They become signable once the Ika network
													completes them — usually a few seconds.
													<div className="mt-1 font-mono text-[10.5px] tabular text-text-4 break-all">
														{done.digest}
													</div>
												</div>
											</div>
											<div className="mt-5 flex justify-end">
												<Button variant="primary" size="default" onClick={closeAndReset}>
													Done
												</Button>
											</div>
										</div>
									) : (
										<div className="px-5 sm:px-7 pb-6 sm:pb-7 space-y-4">
											<div className="flex items-center gap-3">
												<label className="smallcaps text-text-3" htmlFor="replenish-count">
													Count
												</label>
												<input
													id="replenish-count"
													type="number"
													min={1}
													max={50}
													value={count}
													onChange={(e) => {
														const n = parseInt(e.target.value, 10);
														if (Number.isFinite(n) && n > 0) setCount(Math.min(n, 50));
													}}
													disabled={submitting}
													className="w-20 px-2 h-9 bg-surface border border-border rounded-[var(--radius-input)] font-mono text-[13px] tabular text-text focus:outline-none focus:border-clay focus:ring-1 focus:ring-clay/30 disabled:opacity-40"
												/>
												<span className="smallcaps text-text-4">
													{(Number(totalIka) / 1e9).toFixed(2)} IKA ·{' '}
													{(Number(totalSui) / 1e9).toFixed(3)} SUI
												</span>
											</div>

											{!account ? (
												walletReconnecting ? (
													<span className="smallcaps text-text-3 inline-flex items-center gap-1.5">
														<Loader2 className="h-3 w-3 animate-spin" />
														Reconnecting wallet…
													</span>
												) : (
													<div className="flex flex-col sm:flex-row sm:items-center gap-3">
														<span className="smallcaps text-clay inline-flex items-center gap-1.5">
															<AlertCircle className="h-3 w-3" />
															Connect a wallet to pay
														</span>
														<WalletConnect />
													</div>
												)
											) : (
												<div className="flex flex-wrap items-center justify-between gap-3 pt-1">
													<span className="smallcaps text-text-3 inline-flex items-center gap-1.5">
														<Wallet className="h-3 w-3" />
														{`${account.address.slice(0, 6)}…${account.address.slice(-4)}`}
													</span>
													<div className="flex items-center gap-2">
														<Button
															variant="ghost"
															size="default"
															disabled={submitting}
															onClick={closeAndReset}
														>
															Cancel
														</Button>
														<Button
															variant="primary"
															size="default"
															disabled={submitting || count < 1}
															onClick={handleSubmit}
														>
															{submitting ? (
																<>
																	<Loader2 className="h-3.5 w-3.5 animate-spin" />
																	Warming…
																</>
															) : (
																<>
																	<RefreshCw className="h-3.5 w-3.5" />
																	Warm {count} presign{count === 1 ? '' : 's'}
																</>
															)}
														</Button>
													</div>
												</div>
											)}

											{error && (
												<div className="flex items-start gap-2 text-[12.5px] text-clay leading-[1.55]">
													<AlertCircle className="h-3.5 w-3.5 mt-0.5 flex-none" />
													{error}
												</div>
											)}
										</div>
									)}
								</motion.div>
							</motion.div>
						)}
					</AnimatePresence>,
					document.body,
				)}
		</>
	);
}
