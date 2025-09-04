import CodeBlock from '@theme/CodeBlock';
import React, { useState } from 'react';

import styles from './Prerequisites.module.css';

export default function Prerequisites({ items }) {
	const [selectedMethods, setSelectedMethods] = useState({});

	const handleMethodChange = (itemIndex, methodIndex) => {
		setSelectedMethods((prev) => ({
			...prev,
			[itemIndex]: methodIndex,
		}));
	};

	return (
		<div className={styles.prerequisites}>
			{items.map((item, index) => (
				<div key={index} className={styles.prerequisiteItem}>
					<div className={styles.header}>
						<h4 className={styles.title}>{item.name}</h4>
						{item.link && (
							<a
								href={item.link.url}
								target="_blank"
								rel="noopener noreferrer"
								className={styles.link}
							>
								📖 {item.link.text}
							</a>
						)}
					</div>

					{item.description && <p className={styles.description}>{item.description}</p>}

					{/* Single installation method (backward compatibility) */}
					{item.command && !item.methods && (
						<div className={styles.commandSection}>
							<span className={styles.commandLabel}>Quick install:</span>
							<CodeBlock language="bash">{item.command}</CodeBlock>
						</div>
					)}

					{/* Multiple installation methods */}
					{item.methods && (
						<div className={styles.methodsSection}>
							<div className={styles.methodTabs}>
								{item.methods.map((method, methodIndex) => (
									<button
										key={methodIndex}
										className={`${styles.methodTab} ${
											(selectedMethods[index] || 0) === methodIndex ? styles.active : ''
										}`}
										onClick={() => handleMethodChange(index, methodIndex)}
									>
										{method.name}
									</button>
								))}
							</div>
							<div className={styles.methodContent}>
								{item.methods[selectedMethods[index] || 0] && (
									<>
										{item.methods[selectedMethods[index] || 0].description && (
											<p className={styles.methodDescription}>
												{item.methods[selectedMethods[index] || 0].description}
											</p>
										)}
										{item.methods[selectedMethods[index] || 0].command && (
											<CodeBlock language="bash">
												{item.methods[selectedMethods[index] || 0].command}
											</CodeBlock>
										)}
										{item.methods[selectedMethods[index] || 0].link && (
											<div className={styles.methodLink}>
												<a
													href={item.methods[selectedMethods[index] || 0].link.url}
													target="_blank"
													rel="noopener noreferrer"
													className={styles.methodLinkButton}
												>
													📖 {item.methods[selectedMethods[index] || 0].link.text}
												</a>
											</div>
										)}
										{item.methods[selectedMethods[index] || 0].steps && (
											<ol className={styles.stepsList}>
												{item.methods[selectedMethods[index] || 0].steps.map((step, stepIndex) => (
													<li key={stepIndex} className={styles.step}>
														{step}
													</li>
												))}
											</ol>
										)}
									</>
								)}
							</div>
						</div>
					)}
				</div>
			))}
		</div>
	);
}
