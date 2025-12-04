import { ReactNode } from 'react';

import { Button } from '../ui/button';

interface EmptyStateProps {
	icon?: ReactNode;
	title: string;
	description?: string;
	action?: {
		label: string;
		onClick: () => void;
	};
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
	return (
		<div className="flex flex-col items-center justify-center py-12 px-4 text-center">
			{icon && <div className="mb-4 text-muted-foreground">{icon}</div>}
			<h3 className="text-lg font-semibold mb-1">{title}</h3>
			{description && <p className="text-sm text-muted-foreground mb-4 max-w-md">{description}</p>}
			{action && (
				<Button onClick={action.onClick} variant="default">
					{action.label}
				</Button>
			)}
		</div>
	);
}
