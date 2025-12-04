'use client';

import { useState } from 'react';

import { showErrorToast, showSuccessToast } from '@/lib/error-handling';

import { Alert, AlertDescription } from '../ui/alert';
import { Button } from '../ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../ui/dialog';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { RadioGroup, RadioGroupItem } from '../ui/radio-group';

interface ChangeThresholdModalProps {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	onChangeApprovalThreshold: (newThreshold: number) => Promise<void>;
	onChangeRejectionThreshold: (newThreshold: number) => Promise<void>;
	onChangeExpirationDuration?: (durationSeconds: number) => Promise<void>;
	currentApprovalThreshold: number;
	currentRejectionThreshold: number;
	currentExpirationDuration?: number; // in seconds
	memberCount: number;
}

export function ChangeThresholdModal({
	open,
	onOpenChange,
	onChangeApprovalThreshold,
	onChangeRejectionThreshold,
	onChangeExpirationDuration,
	currentApprovalThreshold,
	currentRejectionThreshold,
	currentExpirationDuration,
	memberCount,
}: ChangeThresholdModalProps) {
	const [thresholdType, setThresholdType] = useState<'approval' | 'rejection' | 'expiration'>(
		'approval',
	);
	const [newValue, setNewValue] = useState('');
	const [isSubmitting, setIsSubmitting] = useState(false);

	const maxApproval = memberCount;
	const maxRejection = memberCount - 1;

	const isValid =
		Number(newValue) > 0 &&
		(thresholdType === 'approval'
			? Number(newValue) <= maxApproval
			: thresholdType === 'rejection'
				? Number(newValue) <= maxRejection
				: true); // No max for expiration

	const handleSubmit = async () => {
		if (!isValid) {
			showErrorToast('Invalid value');
			return;
		}

		setIsSubmitting(true);
		try {
			if (thresholdType === 'approval') {
				await onChangeApprovalThreshold(Number(newValue));
				showSuccessToast('Approval threshold change request created!');
			} else if (thresholdType === 'rejection') {
				await onChangeRejectionThreshold(Number(newValue));
				showSuccessToast('Rejection threshold change request created!');
			} else if (thresholdType === 'expiration' && onChangeExpirationDuration) {
				await onChangeExpirationDuration(Number(newValue));
				showSuccessToast('Expiration duration change request created!');
			}

			setNewValue('');
			onOpenChange(false);
		} catch (error) {
			showErrorToast(error, 'Failed to create change request');
		} finally {
			setIsSubmitting(false);
		}
	};

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent className="max-w-md">
				<DialogHeader>
					<DialogTitle>Change Settings</DialogTitle>
					<DialogDescription>
						Change thresholds or expiration duration. This requires approval from other members.
					</DialogDescription>
				</DialogHeader>

				<Alert>
					<AlertDescription className="text-sm">
						💡 This will create a request that needs to be approved by other multisig members before
						taking effect.
					</AlertDescription>
				</Alert>

				<div className="space-y-4">
					<div className="space-y-3">
						<Label className="text-base font-semibold">Select Setting Type</Label>
						<RadioGroup value={thresholdType} onValueChange={(v: any) => setThresholdType(v)}>
							<div className="flex items-start space-x-3 p-3 border rounded-lg hover:bg-muted/50 transition-colors">
								<RadioGroupItem value="approval" id="approval" className="mt-0.5" />
								<div className="flex-1">
									<Label htmlFor="approval" className="font-medium cursor-pointer">
										Approval Threshold
									</Label>
									<p className="text-xs text-muted-foreground mt-1">
										Number of approvals needed to execute a request (currently{' '}
										{currentApprovalThreshold})
									</p>
								</div>
							</div>
							<div className="flex items-start space-x-3 p-3 border rounded-lg hover:bg-muted/50 transition-colors">
								<RadioGroupItem value="rejection" id="rejection" className="mt-0.5" />
								<div className="flex-1">
									<Label htmlFor="rejection" className="font-medium cursor-pointer">
										Rejection Threshold
									</Label>
									<p className="text-xs text-muted-foreground mt-1">
										Number of rejections needed to cancel a request (currently{' '}
										{currentRejectionThreshold})
									</p>
								</div>
							</div>
							{onChangeExpirationDuration && currentExpirationDuration !== undefined && (
								<div className="flex items-start space-x-3 p-3 border rounded-lg hover:bg-muted/50 transition-colors">
									<RadioGroupItem value="expiration" id="expiration" className="mt-0.5" />
									<div className="flex-1">
										<Label htmlFor="expiration" className="font-medium cursor-pointer">
											Request Expiration Duration
										</Label>
										<p className="text-xs text-muted-foreground mt-1">
											How long requests remain valid (currently {currentExpirationDuration} seconds)
										</p>
									</div>
								</div>
							)}
						</RadioGroup>
					</div>

					<div className="space-y-2">
						<Label htmlFor="threshold-value">
							{thresholdType === 'expiration' ? 'New Duration (seconds)' : 'New Value'}{' '}
							<span className="text-destructive">*</span>
						</Label>
						<Input
							id="threshold-value"
							type="number"
							min={1}
							max={
								thresholdType === 'approval'
									? maxApproval
									: thresholdType === 'rejection'
										? maxRejection
										: undefined
							}
							placeholder={
								thresholdType === 'approval'
									? `1 to ${maxApproval}`
									: thresholdType === 'rejection'
										? `1 to ${maxRejection}`
										: 'Enter seconds'
							}
							value={newValue}
							onChange={(e) => setNewValue(e.target.value)}
							className={
								newValue && isValid
									? 'border-green-500 dark:border-green-600'
									: newValue
										? 'border-red-500 dark:border-red-600'
										: ''
							}
						/>
						<div className="flex items-start gap-2">
							<p className="text-xs text-muted-foreground">
								{thresholdType === 'approval'
									? `Valid range: 1 to ${maxApproval} (total members: ${memberCount})`
									: thresholdType === 'rejection'
										? `Valid range: 1 to ${maxRejection} (one less than total members)`
										: 'How many seconds before requests expire'}
							</p>
						</div>
						{newValue && !isValid && (
							<p className="text-xs text-red-500">
								{thresholdType === 'approval'
									? `Value must be between 1 and ${maxApproval}`
									: thresholdType === 'rejection'
										? `Value must be between 1 and ${maxRejection}`
										: 'Value must be greater than 0'}
							</p>
						)}
					</div>
				</div>

				<div className="flex justify-end gap-2">
					<Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
						Cancel
					</Button>
					<Button onClick={handleSubmit} disabled={!isValid || isSubmitting}>
						{isSubmitting ? 'Creating Request...' : 'Create Request'}
					</Button>
				</div>
			</DialogContent>
		</Dialog>
	);
}
