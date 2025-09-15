import { AlertCircle, Plus, Settings, Trash2, Users } from 'lucide-react';
import { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export interface MultisigParams {
	members: string[];
	approvalThreshold: number;
	rejectionThreshold: number;
	expirationDuration: number;
}

interface CreateMultisigModalProps {
	isOpen: boolean;
	onClose: () => void;
	onSubmit: (params: MultisigParams) => void;
	isCreating: boolean;
}

export function CreateMultisigModal({
	isOpen,
	onClose,
	onSubmit,
	isCreating,
}: CreateMultisigModalProps) {
	const [members, setMembers] = useState<string[]>([]);
	const [approvalThreshold, setApprovalThreshold] = useState(0);
	const [rejectionThreshold, setRejectionThreshold] = useState(0);
	const [expirationDuration, setExpirationDuration] = useState(1000000000000000);
	const [errors, setErrors] = useState<{ [key: string]: string }>({});

	const addMember = () => {
		setMembers([...members, '']);
	};

	const removeMember = (index: number) => {
		if (members.length > 1) {
			setMembers(members.filter((_, i) => i !== index));
		}
	};

	const updateMember = (index: number, value: string) => {
		const newMembers = [...members];
		newMembers[index] = value;
		setMembers(newMembers);
	};

	const validateForm = () => {
		const newErrors: { [key: string]: string } = {};

		// Validate members
		if (members.length < 1) {
			newErrors.members = 'At least one member is required';
		}

		members.forEach((member, index) => {
			if (!member.trim()) {
				newErrors[`member${index}`] = 'Member address cannot be empty';
			} else if (!member.startsWith('0x')) {
				newErrors[`member${index}`] = 'Member address must start with 0x';
			} else if (member.length !== 66) {
				newErrors[`member${index}`] = 'Member address must be 66 characters long';
			}
		});

		// Check for duplicate members
		const uniqueMembers = new Set(members.filter((m) => m.trim()));
		if (uniqueMembers.size !== members.filter((m) => m.trim()).length) {
			newErrors.members = 'Duplicate member addresses are not allowed';
		}

		// Validate thresholds
		if (approvalThreshold < 1) {
			newErrors.approvalThreshold = 'Approval threshold must be at least 1';
		}
		if (approvalThreshold > members.length) {
			newErrors.approvalThreshold = 'Approval threshold cannot exceed number of members';
		}
		if (rejectionThreshold < 1) {
			newErrors.rejectionThreshold = 'Rejection threshold must be at least 1';
		}
		if (rejectionThreshold > members.length) {
			newErrors.rejectionThreshold = 'Rejection threshold cannot exceed number of members';
		}

		// Validate expiration duration
		if (expirationDuration < 1) {
			newErrors.expirationDuration = 'Expiration duration must be positive';
		}

		setErrors(newErrors);
		return Object.keys(newErrors).length === 0;
	};

	const handleSubmit = () => {
		if (validateForm()) {
			onSubmit({
				members: members.filter((m) => m.trim()),
				approvalThreshold,
				rejectionThreshold,
				expirationDuration,
			});
		}
	};

	const handleClose = () => {
		if (!isCreating) {
			onClose();
		}
	};

	return (
		<Dialog open={isOpen} onOpenChange={handleClose}>
			<DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
				<DialogHeader>
					<DialogTitle className="flex items-center gap-2">
						<Settings className="w-5 h-5" />
						Create Multisig Wallet
					</DialogTitle>
					<DialogDescription>
						Configure the parameters for your new multisignature wallet. All fields are required.
					</DialogDescription>
				</DialogHeader>

				<div className="space-y-6">
					{/* Members Section */}
					<Card>
						<CardHeader>
							<CardTitle className="flex items-center gap-2 text-base">
								<Users className="w-4 h-4" />
								Members ({members.length})
							</CardTitle>
							<CardDescription>
								Add wallet addresses that will be members of this multisig
							</CardDescription>
						</CardHeader>
						<CardContent className="space-y-3">
							{members.map((member, index) => (
								<div key={index} className="flex gap-2">
									<div className="flex-1">
										<Label htmlFor={`member-${index}`} className="sr-only">
											Member {index + 1}
										</Label>
										<Input
											id={`member-${index}`}
											placeholder={`Member ${index + 1} address (0x...)`}
											value={member}
											onChange={(e) => updateMember(index, e.target.value)}
											disabled={isCreating}
											className={errors[`member${index}`] ? 'border-destructive' : ''}
										/>
										{errors[`member${index}`] && (
											<p className="text-sm text-destructive mt-1">{errors[`member${index}`]}</p>
										)}
									</div>
									{members.length > 1 && (
										<Button
											variant="outline"
											size="sm"
											onClick={() => removeMember(index)}
											disabled={isCreating}
											className="px-3"
										>
											<Trash2 className="w-4 h-4" />
										</Button>
									)}
								</div>
							))}

							{errors.members && (
								<div className="flex items-center gap-2 p-2 bg-destructive/10 border border-destructive/20 rounded">
									<AlertCircle className="w-4 h-4 text-destructive" />
									<p className="text-sm text-destructive">{errors.members}</p>
								</div>
							)}

							<Button
								variant="outline"
								size="sm"
								onClick={addMember}
								disabled={isCreating}
								className="w-full"
							>
								<Plus className="w-4 h-4 mr-2" />
								Add Member
							</Button>
						</CardContent>
					</Card>

					{/* Thresholds Section */}
					<Card>
						<CardHeader>
							<CardTitle className="text-base">Voting Thresholds</CardTitle>
							<CardDescription>
								Set the minimum number of approvals and rejections needed for decisions
							</CardDescription>
						</CardHeader>
						<CardContent className="grid grid-cols-2 gap-4">
							<div>
								<Label htmlFor="approval-threshold">Approval Threshold</Label>
								<Input
									id="approval-threshold"
									type="number"
									min={1}
									max={members.length}
									value={approvalThreshold}
									onChange={(e) => setApprovalThreshold(parseInt(e.target.value) || 1)}
									disabled={isCreating}
									className={errors.approvalThreshold ? 'border-destructive' : ''}
								/>
								{errors.approvalThreshold && (
									<p className="text-sm text-destructive mt-1">{errors.approvalThreshold}</p>
								)}
								<p className="text-xs text-muted-foreground mt-1">
									Minimum approvals needed to execute
								</p>
							</div>

							<div>
								<Label htmlFor="rejection-threshold">Rejection Threshold</Label>
								<Input
									id="rejection-threshold"
									type="number"
									min={1}
									max={members.length}
									value={rejectionThreshold}
									onChange={(e) => setRejectionThreshold(parseInt(e.target.value) || 1)}
									disabled={isCreating}
									className={errors.rejectionThreshold ? 'border-destructive' : ''}
								/>
								{errors.rejectionThreshold && (
									<p className="text-sm text-destructive mt-1">{errors.rejectionThreshold}</p>
								)}
								<p className="text-xs text-muted-foreground mt-1">
									Minimum rejections to block execution
								</p>
							</div>
						</CardContent>
					</Card>

					{/* Expiration Duration Section */}
					<Card>
						<CardHeader>
							<CardTitle className="text-base">Request Expiration</CardTitle>
							<CardDescription>
								Set how long requests remain valid before they expire
							</CardDescription>
						</CardHeader>
						<CardContent>
							<Label htmlFor="expiration-duration">Expiration Duration (nanoseconds)</Label>
							<Input
								id="expiration-duration"
								type="number"
								min={1}
								value={expirationDuration}
								onChange={(e) => setExpirationDuration(parseInt(e.target.value) || 1)}
								disabled={isCreating}
								className={errors.expirationDuration ? 'border-destructive' : ''}
							/>
							{errors.expirationDuration && (
								<p className="text-sm text-destructive mt-1">{errors.expirationDuration}</p>
							)}
							<p className="text-xs text-muted-foreground mt-1">
								Default: {expirationDuration.toLocaleString()} ns (~11.5 days)
							</p>
						</CardContent>
					</Card>

					{/* Summary */}
					<Card className="bg-muted/50">
						<CardHeader>
							<CardTitle className="text-base">Summary</CardTitle>
						</CardHeader>
						<CardContent>
							<div className="text-sm space-y-1">
								<p>
									<strong>Members:</strong> {members.filter((m) => m.trim()).length}
								</p>
								<p>
									<strong>Approval Threshold:</strong> {approvalThreshold} of{' '}
									{members.filter((m) => m.trim()).length}
								</p>
								<p>
									<strong>Rejection Threshold:</strong> {rejectionThreshold} of{' '}
									{members.filter((m) => m.trim()).length}
								</p>
								<p>
									<strong>Configuration:</strong> {approvalThreshold}-of-
									{members.filter((m) => m.trim()).length} multisig
								</p>
							</div>
						</CardContent>
					</Card>
				</div>

				<DialogFooter>
					<Button variant="outline" onClick={handleClose} disabled={isCreating}>
						Cancel
					</Button>
					<Button onClick={handleSubmit} disabled={isCreating} className="min-w-[120px]">
						{isCreating ? (
							<>
								<div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
								Creating...
							</>
						) : (
							'Create Multisig'
						)}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}
