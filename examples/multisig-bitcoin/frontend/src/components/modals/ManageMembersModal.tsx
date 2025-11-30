'use client';

import { Check, X } from 'lucide-react';
import { useState } from 'react';

import { showErrorToast, showSuccessToast } from '@/lib/error-handling';
import { isValidSuiAddress, shorten } from '@/lib/formatting';

import { Alert, AlertDescription } from '../ui/alert';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../ui/dialog';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs';

interface ManageMembersModalProps {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	onAddMember: (address: string) => Promise<void>;
	onRemoveMember: (address: string) => Promise<void>;
	currentMembers: string[];
}

export function ManageMembersModal({
	open,
	onOpenChange,
	onAddMember,
	onRemoveMember,
	currentMembers,
}: ManageMembersModalProps) {
	const [addAddress, setAddAddress] = useState('');
	const [removeAddress, setRemoveAddress] = useState('');
	const [isSubmitting, setIsSubmitting] = useState(false);

	const isAddAddressValid = addAddress.trim() && isValidSuiAddress(addAddress.trim());
	const isAddressDuplicate = currentMembers.includes(addAddress.trim());

	const isRemoveAddressValid = removeAddress.trim() && isValidSuiAddress(removeAddress.trim());
	const isRemoveAddressMember = currentMembers.includes(removeAddress.trim());

	const handleAddMember = async () => {
		const address = addAddress.trim();
		if (!isValidSuiAddress(address)) {
			showErrorToast('Invalid Sui address');
			return;
		}

		if (currentMembers.includes(address)) {
			showErrorToast('This address is already a member');
			return;
		}

		setIsSubmitting(true);
		try {
			await onAddMember(address);
			showSuccessToast('Add member request created!');
			setAddAddress('');
			onOpenChange(false);
		} catch (error) {
			showErrorToast(error, 'Failed to create add member request');
		} finally {
			setIsSubmitting(false);
		}
	};

	const handleRemoveMember = async () => {
		const address = removeAddress.trim();
		if (!isValidSuiAddress(address)) {
			showErrorToast('Invalid Sui address');
			return;
		}

		if (!currentMembers.includes(address)) {
			showErrorToast('This address is not a member');
			return;
		}

		setIsSubmitting(true);
		try {
			await onRemoveMember(address);
			showSuccessToast('Remove member request created!');
			setRemoveAddress('');
			onOpenChange(false);
		} catch (error) {
			showErrorToast(error, 'Failed to create remove member request');
		} finally {
			setIsSubmitting(false);
		}
	};

	const resetForm = () => {
		setAddAddress('');
		setRemoveAddress('');
		setIsSubmitting(false);
	};

	const handleOpenChange = (newOpen: boolean) => {
		if (!newOpen && !isSubmitting) {
			resetForm();
		}
		onOpenChange(newOpen);
	};

	return (
		<Dialog open={open} onOpenChange={handleOpenChange}>
			<DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
				<DialogHeader>
					<DialogTitle>Manage Members</DialogTitle>
					<DialogDescription>
						Add or remove members from this multisig. Changes require approval from other members.
					</DialogDescription>
				</DialogHeader>

				<Alert>
					<AlertDescription>
						These actions will create requests that need to be approved by other multisig members
						before taking effect.
					</AlertDescription>
				</Alert>

				{/* Current Members Display */}
				<div className="space-y-2">
					<div className="flex items-center justify-between">
						<Label className="text-sm font-medium">Current Members</Label>
						<Badge variant="secondary">{currentMembers.length} members</Badge>
					</div>
					<div className="border rounded-lg divide-y max-h-32 overflow-y-auto">
						{currentMembers.map((member, index) => (
							<div
								key={member}
								className="flex items-center gap-3 p-2 text-sm hover:bg-muted/50 transition-colors"
							>
								<Badge variant="outline" className="font-mono text-xs">
									#{index + 1}
								</Badge>
								<code className="flex-1 truncate" title={member}>
									{shorten(member, 16)}
								</code>
							</div>
						))}
					</div>
				</div>

				<Tabs defaultValue="add" className="w-full">
					<TabsList className="grid w-full grid-cols-2">
						<TabsTrigger value="add">Add Member</TabsTrigger>
						<TabsTrigger value="remove">Remove Member</TabsTrigger>
					</TabsList>

					<TabsContent value="add" className="space-y-4">
						<div className="space-y-2">
							<Label htmlFor="add-address">
								New Member Address <span className="text-destructive">*</span>
							</Label>
							<div className="relative">
								<Input
									id="add-address"
									placeholder="Enter Sui address (0x...)"
									value={addAddress}
									onChange={(e) => setAddAddress(e.target.value)}
									className={
										addAddress.trim()
											? isAddAddressValid && !isAddressDuplicate
												? 'border-green-500 dark:border-green-600'
												: 'border-red-500 dark:border-red-600'
											: ''
									}
								/>
								{addAddress.trim() && (
									<div className="absolute right-3 top-1/2 -translate-y-1/2">
										{isAddAddressValid && !isAddressDuplicate ? (
											<Check className="h-4 w-4 text-green-500" />
										) : (
											<X className="h-4 w-4 text-red-500" />
										)}
									</div>
								)}
							</div>
							{addAddress.trim() && !isAddAddressValid && (
								<p className="text-xs text-red-500">Invalid Sui address format</p>
							)}
							{isAddressDuplicate && (
								<p className="text-xs text-red-500">This address is already a member</p>
							)}
							{isAddAddressValid && !isAddressDuplicate && (
								<p className="text-xs text-green-600 dark:text-green-500">
									Valid address - ready to create request
								</p>
							)}
						</div>

						<div className="bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-md p-3">
							<p className="text-sm text-blue-900 dark:text-blue-100">
								Adding a member increases the total number of possible signers. You may need to
								adjust approval thresholds accordingly.
							</p>
						</div>

						<div className="flex justify-end">
							<Button
								onClick={handleAddMember}
								disabled={!isAddAddressValid || isAddressDuplicate || isSubmitting}
							>
								{isSubmitting ? 'Creating Request...' : 'Create Add Member Request'}
							</Button>
						</div>
					</TabsContent>

					<TabsContent value="remove" className="space-y-4">
						<div className="space-y-2">
							<Label htmlFor="remove-address">
								Member Address to Remove <span className="text-destructive">*</span>
							</Label>
							<div className="relative">
								<Input
									id="remove-address"
									placeholder="Enter Sui address (0x...)"
									value={removeAddress}
									onChange={(e) => setRemoveAddress(e.target.value)}
									className={
										removeAddress.trim()
											? isRemoveAddressValid && isRemoveAddressMember
												? 'border-green-500 dark:border-green-600'
												: 'border-red-500 dark:border-red-600'
											: ''
									}
								/>
								{removeAddress.trim() && (
									<div className="absolute right-3 top-1/2 -translate-y-1/2">
										{isRemoveAddressValid && isRemoveAddressMember ? (
											<Check className="h-4 w-4 text-green-500" />
										) : (
											<X className="h-4 w-4 text-red-500" />
										)}
									</div>
								)}
							</div>
							{removeAddress.trim() && !isRemoveAddressValid && (
								<p className="text-xs text-red-500">Invalid Sui address format</p>
							)}
							{isRemoveAddressValid && !isRemoveAddressMember && (
								<p className="text-xs text-red-500">This address is not a current member</p>
							)}
							{isRemoveAddressValid && isRemoveAddressMember && (
								<p className="text-xs text-green-600 dark:text-green-500">
									Valid member address - ready to create request
								</p>
							)}
						</div>

						<div className="bg-yellow-50 dark:bg-yellow-950/20 border border-yellow-200 dark:border-yellow-800 rounded-md p-3">
							<p className="text-sm text-yellow-900 dark:text-yellow-100 font-medium mb-1">
								⚠️ Warning
							</p>
							<p className="text-sm text-yellow-900 dark:text-yellow-100">
								Removing a member reduces the total number of signers. Ensure approval thresholds
								will still be achievable after removal (currently {currentMembers.length} members).
							</p>
						</div>

						<div className="flex justify-end">
							<Button
								onClick={handleRemoveMember}
								disabled={!isRemoveAddressValid || !isRemoveAddressMember || isSubmitting}
								variant="destructive"
							>
								{isSubmitting ? 'Creating Request...' : 'Create Remove Member Request'}
							</Button>
						</div>
					</TabsContent>
				</Tabs>
			</DialogContent>
		</Dialog>
	);
}
