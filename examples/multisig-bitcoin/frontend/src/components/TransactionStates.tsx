import { AlertCircle, ArrowDown, CheckCircle, Circle, Loader } from 'lucide-react';
import { useState } from 'react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export interface TransactionState {
	id: string;
	title: string;
	description: string;
	status: 'pending' | 'in_progress' | 'completed' | 'error';
	error?: string;
}

export interface TransactionStatesProps {
	states: TransactionState[];
	title?: string;
	className?: string;
}

export function TransactionStates({
	states,
	title = 'Transaction Progress',
	className,
}: TransactionStatesProps) {
	const getStatusIcon = (status: TransactionState['status']) => {
		switch (status) {
			case 'completed':
				return <CheckCircle className="w-5 h-5 text-green-500" />;
			case 'in_progress':
				return <Loader className="w-5 h-5 text-blue-500 animate-spin" />;
			case 'error':
				return <AlertCircle className="w-5 h-5 text-red-500" />;
			default:
				return <Circle className="w-5 h-5 text-gray-400" />;
		}
	};

	const getStatusColor = (status: TransactionState['status']) => {
		switch (status) {
			case 'completed':
				return 'bg-green-100 border-green-200 text-green-800 dark:bg-green-900 dark:border-green-700 dark:text-green-200';
			case 'in_progress':
				return 'bg-blue-100 border-blue-200 text-blue-800 dark:bg-blue-900 dark:border-blue-700 dark:text-blue-200';
			case 'error':
				return 'bg-red-100 border-red-200 text-red-800 dark:bg-red-900 dark:border-red-700 dark:text-red-200';
			default:
				return 'bg-gray-100 border-gray-200 text-gray-600 dark:bg-gray-800 dark:border-gray-700 dark:text-gray-400';
		}
	};

	const getStatusText = (status: TransactionState['status']) => {
		switch (status) {
			case 'completed':
				return 'Completed';
			case 'in_progress':
				return 'In Progress';
			case 'error':
				return 'Error';
			default:
				return 'Pending';
		}
	};

	return (
		<Card className={className}>
			<CardHeader>
				<CardTitle className="flex items-center gap-2">
					{title}
					<Badge
						variant="outline"
						className={`ml-auto ${
							states.some((s) => s.status === 'error')
								? 'border-red-500 text-red-500'
								: states.every((s) => s.status === 'completed')
									? 'border-green-500 text-green-500'
									: states.some((s) => s.status === 'in_progress')
										? 'border-blue-500 text-blue-500'
										: 'border-gray-500 text-gray-500'
						}`}
					>
						{states.some((s) => s.status === 'error')
							? 'Failed'
							: states.every((s) => s.status === 'completed')
								? 'Completed'
								: states.some((s) => s.status === 'in_progress')
									? 'In Progress'
									: 'Pending'}
					</Badge>
				</CardTitle>
			</CardHeader>
			<CardContent>
				<div className="space-y-4">
					{states.map((state, index) => (
						<div key={state.id}>
							<div className="flex items-start gap-3">
								<div className="flex-shrink-0 mt-0.5">{getStatusIcon(state.status)}</div>
								<div className="flex-1 min-w-0">
									<div className="flex items-center gap-2 mb-1">
										<h4 className="font-medium text-foreground">{state.title}</h4>
										<Badge variant="outline" className={`text-xs ${getStatusColor(state.status)}`}>
											{getStatusText(state.status)}
										</Badge>
									</div>
									<p className="text-sm text-muted-foreground">{state.description}</p>
									{state.error && (
										<div className="mt-2 p-2 bg-red-50 border border-red-200 rounded text-sm text-red-700 dark:bg-red-950 dark:border-red-800 dark:text-red-300">
											<strong>Error:</strong> {state.error}
										</div>
									)}
								</div>
							</div>
							{index < states.length - 1 && (
								<div className="flex justify-center my-2">
									<ArrowDown className="w-4 h-4 text-gray-400" />
								</div>
							)}
						</div>
					))}
				</div>
			</CardContent>
		</Card>
	);
}

// Hook for managing transaction states
export function useTransactionStates(initialStates: Omit<TransactionState, 'status'>[]) {
	const [states, setStates] = useState<TransactionState[]>(
		initialStates.map((state) => ({ ...state, status: 'pending' as const })),
	);

	const updateState = (id: string, updates: Partial<TransactionState>) => {
		setStates((prev) => prev.map((state) => (state.id === id ? { ...state, ...updates } : state)));
	};

	const setStateStatus = (id: string, status: TransactionState['status'], error?: string) => {
		updateState(id, { status, error });
	};

	const resetStates = () => {
		setStates((prev) => prev.map((state) => ({ ...state, status: 'pending', error: undefined })));
	};

	return {
		states,
		updateState,
		setStateStatus,
		resetStates,
	};
}
