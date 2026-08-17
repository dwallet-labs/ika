'use client';

import { Button, Card } from '@fesal-packages/ikavery-frontend-ui';
import { AlertCircle, ArrowLeft } from 'lucide-react';
import { useRouter } from 'next/navigation';

interface Props {
	recoveryId: string;
	message: string;
	/** Optional headline shown above the message. */
	title?: string;
}

export function ErrorShell({ recoveryId, message, title }: Props) {
	const router = useRouter();
	return (
		<div className="max-w-[640px] mx-auto py-10">
			{title ? (
				<button
					type="button"
					onClick={() => router.push(`/vault/${recoveryId}`)}
					className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-6"
				>
					<ArrowLeft className="h-3 w-3" />
					Back to vault
				</button>
			) : null}
			<Card tone="raised" className={title ? 'px-6 py-7' : 'px-6 py-6 border-clay/30'}>
				<div className="flex items-start gap-4">
					<AlertCircle className="h-4 w-4 text-clay mt-1" />
					<div>
						{title && <h2 className="font-display text-[24px] text-text">{title}</h2>}
						<p
							className={
								title
									? 'mt-2 font-mono text-[11px] tabular text-text-3 break-all'
									: 'text-[13px] text-text-2'
							}
						>
							{message}
						</p>
						{!title && (
							<Button
								variant="ghost"
								size="default"
								className="mt-4"
								onClick={() => router.push(`/vault/${recoveryId}`)}
							>
								<ArrowLeft className="h-3.5 w-3.5" />
								Back to vault
							</Button>
						)}
					</div>
				</div>
			</Card>
		</div>
	);
}
