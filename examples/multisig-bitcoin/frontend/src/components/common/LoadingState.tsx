import { Skeleton } from '../ui/skeleton';

export function LoadingState() {
	return (
		<div className="space-y-4">
			<Skeleton className="h-12 w-full" />
			<Skeleton className="h-32 w-full" />
			<Skeleton className="h-32 w-full" />
		</div>
	);
}

export function LoadingSidebar() {
	return (
		<div className="space-y-1">
			<Skeleton className="h-[52px] w-full rounded-lg" />
			<Skeleton className="h-[52px] w-full rounded-lg" />
			<Skeleton className="h-[52px] w-full rounded-lg" />
			<Skeleton className="h-[52px] w-full rounded-lg" />
		</div>
	);
}
