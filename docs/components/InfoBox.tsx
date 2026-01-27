'use client';

import { Callout } from 'fumadocs-ui/components/callout';
import {
	AlertTriangle,
	Construction as ConstructionIcon,
	FileCode,
	Info as InfoIcon,
	Lightbulb,
	StickyNote,
} from 'lucide-react';
import React from 'react';

type InfoBoxType = 'info' | 'tip' | 'warning' | 'example' | 'note';

interface InfoBoxProps {
	type?: InfoBoxType;
	title?: string;
	children: React.ReactNode;
}

const typeMapping: Record<InfoBoxType, 'info' | 'warn' | 'error'> = {
	info: 'info',
	tip: 'info',
	warning: 'warn',
	example: 'info',
	note: 'info',
};

const iconMapping: Record<InfoBoxType, React.ReactNode> = {
	info: <InfoIcon className="h-5 w-5" />,
	tip: <Lightbulb className="h-5 w-5" />,
	warning: <AlertTriangle className="h-5 w-5" />,
	example: <FileCode className="h-5 w-5" />,
	note: <StickyNote className="h-5 w-5" />,
};

const defaultTitles: Record<InfoBoxType, string> = {
	info: 'Info',
	tip: 'Tip',
	warning: 'Warning',
	example: 'Example',
	note: 'Note',
};

export default function InfoBox({ type = 'info', title, children }: InfoBoxProps) {
	return (
		<Callout
			type={typeMapping[type]}
			title={
				<span className="inline-flex items-center gap-2">
					{iconMapping[type]}
					{title || defaultTitles[type]}
				</span>
			}
		>
			{children}
		</Callout>
	);
}

// Common presets - matching original API
export function Info({ title, children }: Omit<InfoBoxProps, 'type'>) {
	return (
		<InfoBox type="info" title={title}>
			{children}
		</InfoBox>
	);
}

export function Tip({ title, children }: Omit<InfoBoxProps, 'type'>) {
	return (
		<InfoBox type="tip" title={title}>
			{children}
		</InfoBox>
	);
}

export function Warning({ title, children }: Omit<InfoBoxProps, 'type'>) {
	return (
		<InfoBox type="warning" title={title}>
			{children}
		</InfoBox>
	);
}

export function Example({ title, children }: Omit<InfoBoxProps, 'type'>) {
	return (
		<InfoBox type="example" title={title}>
			{children}
		</InfoBox>
	);
}

export function Note({ title, children }: Omit<InfoBoxProps, 'type'>) {
	return (
		<InfoBox type="note" title={title}>
			{children}
		</InfoBox>
	);
}

export function Construction() {
	return (
		<Callout
			type="warn"
			title={
				<span className="inline-flex items-center gap-2">
					<ConstructionIcon className="h-5 w-5" />
					Under Construction
				</span>
			}
		>
			This SDK is still in an experimental phase. We advise you use the SDK with localnet.
		</Callout>
	);
}
