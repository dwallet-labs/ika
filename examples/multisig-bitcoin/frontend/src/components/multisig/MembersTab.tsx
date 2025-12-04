'use client';

import { UserMinus, UserPlus } from 'lucide-react';

import { shorten } from '@/lib/formatting';

import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';

interface MembersTabProps {
	members: string[];
	approvalThreshold: number;
	rejectionThreshold: number;
	onManageMembers: () => void;
}

export function MembersTab({
	members,
	approvalThreshold,
	rejectionThreshold,
	onManageMembers,
}: MembersTabProps) {
	return (
		<div className="space-y-6">
			<div className="flex items-center justify-between">
				<div>
					<h3 className="text-lg font-semibold">Members</h3>
					<p className="text-sm text-muted-foreground">
						{members.length} member{members.length !== 1 ? 's' : ''} in this multisig
					</p>
				</div>
				<Button onClick={onManageMembers} size="sm">
					<UserPlus className="h-4 w-4 mr-2" />
					Manage Members
				</Button>
			</div>

			<div className="grid grid-cols-2 gap-4">
				<div className="border rounded-lg p-4">
					<div className="text-sm text-muted-foreground mb-1">Approval Threshold</div>
					<div className="text-2xl font-semibold">{approvalThreshold}</div>
					<div className="text-xs text-muted-foreground mt-1">
						out of {members.length} required to approve
					</div>
				</div>
				<div className="border rounded-lg p-4">
					<div className="text-sm text-muted-foreground mb-1">Rejection Threshold</div>
					<div className="text-2xl font-semibold">{rejectionThreshold}</div>
					<div className="text-xs text-muted-foreground mt-1">
						out of {members.length} required to reject
					</div>
				</div>
			</div>

			<div className="border rounded-md">
				<Table>
					<TableHeader>
						<TableRow>
							<TableHead>#</TableHead>
							<TableHead>Address</TableHead>
							<TableHead>Status</TableHead>
						</TableRow>
					</TableHeader>
					<TableBody>
						{members.map((member, index) => (
							<TableRow key={member}>
								<TableCell className="font-medium">{index + 1}</TableCell>
								<TableCell className="font-mono text-sm">{shorten(member, 12)}</TableCell>
								<TableCell>
									<Badge variant="outline">Active</Badge>
								</TableCell>
							</TableRow>
						))}
					</TableBody>
				</Table>
			</div>
		</div>
	);
}
