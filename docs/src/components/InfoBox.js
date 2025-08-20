import React from 'react';

import styles from './InfoBox.module.css';

export default function InfoBox({ type = 'info', title, children }) {
	const typeClass = styles[type] || styles.info;

	return (
		<div className={`${styles.infoBox} ${typeClass}`}>
			{title && <div className={styles.title}>{title}</div>}
			<div className={styles.content}>{children}</div>
		</div>
	);
}

// Common presets
export function Info({ title, children }) {
	return (
		<InfoBox type="info" title={title}>
			{children}
		</InfoBox>
	);
}

export function Tip({ title, children }) {
	return (
		<InfoBox type="tip" title={title}>
			{children}
		</InfoBox>
	);
}

export function Warning({ title, children }) {
	return (
		<InfoBox type="warning" title={title}>
			{children}
		</InfoBox>
	);
}

export function Example({ title, children }) {
	return (
		<InfoBox type="example" title={title}>
			{children}
		</InfoBox>
	);
}

export function Note({ title, children }) {
	return (
		<InfoBox type="note" title={title}>
			{children}
		</InfoBox>
	);
}

export function Construction() {
	return (
		<InfoBox type="warning" title="🚧 Under Construction 🚧">
			This SDK is still in an experimental phase. We advise you use the SDK with localnet.
		</InfoBox>
	);
}
