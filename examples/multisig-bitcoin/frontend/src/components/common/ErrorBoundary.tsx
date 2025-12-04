'use client';

import { Component, ReactNode } from 'react';

import { Alert, AlertDescription, AlertTitle } from '../ui/alert';
import { Button } from '../ui/button';

interface Props {
	children: ReactNode;
}

interface State {
	hasError: boolean;
	error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
	constructor(props: Props) {
		super(props);
		this.state = { hasError: false };
	}

	static getDerivedStateFromError(error: Error): State {
		return { hasError: true, error };
	}

	componentDidCatch(error: Error, errorInfo: any) {
		console.error('ErrorBoundary caught an error:', error, errorInfo);
	}

	render() {
		if (this.state.hasError) {
			return (
				<div className="flex items-center justify-center min-h-screen p-4">
					<div className="max-w-md w-full">
						<Alert variant="destructive">
							<AlertTitle>Something went wrong</AlertTitle>
							<AlertDescription className="mt-2">
								{this.state.error?.message || 'An unexpected error occurred'}
							</AlertDescription>
						</Alert>
						<div className="mt-4 flex gap-2">
							<Button onClick={() => window.location.reload()} variant="default" className="flex-1">
								Reload page
							</Button>
							<Button
								onClick={() => this.setState({ hasError: false })}
								variant="outline"
								className="flex-1"
							>
								Try again
							</Button>
						</div>
					</div>
				</div>
			);
		}

		return this.props.children;
	}
}
