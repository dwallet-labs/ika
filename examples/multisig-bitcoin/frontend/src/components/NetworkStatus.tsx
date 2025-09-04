import { AlertCircle, CheckCircle, Loader2, Network } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useIkaClient } from '@/hooks/ika-client';

export function NetworkStatus() {
	const { ikaClient, isLoading } = useIkaClient();

	if (isLoading) {
		return (
			<Card className="mb-6">
				<CardHeader>
					<CardTitle className="flex items-center gap-2">
						<Loader2 className="w-5 h-5 animate-spin" />
						Initializing IKA Client
					</CardTitle>
					<CardDescription>Setting up connection to IKA network</CardDescription>
				</CardHeader>
				<CardContent>
					<div className="flex items-center gap-2">
						<div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
						<span className="text-sm text-gray-600 dark:text-gray-300">
							Connecting to IKA network...
						</span>
					</div>
				</CardContent>
			</Card>
		);
	}

	if (!ikaClient) {
		return (
			<Card className="mb-6 border-red-200 dark:border-red-800">
				<CardHeader>
					<CardTitle className="flex items-center gap-2 text-red-600 dark:text-red-400">
						<AlertCircle className="w-5 h-5" />
						Connection Failed
					</CardTitle>
					<CardDescription>Unable to connect to IKA network</CardDescription>
				</CardHeader>
				<CardContent>
					<div className="text-sm text-red-600 dark:text-red-400">
						Please check your network connection and try again.
					</div>
				</CardContent>
			</Card>
		);
	}

	return (
		<Card className="mb-6">
			<CardHeader>
				<CardTitle className="flex items-center gap-2">
					<Network className="w-5 h-5" />
					Network Status
				</CardTitle>
				<CardDescription>Connected to IKA network on Sui Mainnet</CardDescription>
			</CardHeader>
			<CardContent>
				<div className="flex items-center gap-2">
					<Badge
						variant="default"
						className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
					>
						<CheckCircle className="w-3 h-3 mr-1" />
						Connected
					</Badge>
					<span className="text-sm text-gray-600 dark:text-gray-300">All systems operational</span>
				</div>
			</CardContent>
		</Card>
	);
}
