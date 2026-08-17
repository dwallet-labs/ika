'use client';

import { ArrowLeft } from 'lucide-react';
import { useRouter } from 'next/navigation';

interface Props {
	recoveryId: string;
	label?: string;
	className?: string;
}

export function BackToVaultLink({ recoveryId, label = 'Back to vault', className }: Props) {
	const router = useRouter();
	return (
		<button
			type="button"
			onClick={() => router.push(`/vault/${recoveryId}`)}
			className={
				className ?? 'smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-6'
			}
		>
			<ArrowLeft className="h-3 w-3" />
			{label}
		</button>
	);
}
