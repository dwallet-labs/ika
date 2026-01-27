'use client';

import { cn } from 'fumadocs-ui/components/api';
import { Check, Copy, ExternalLink } from 'lucide-react';
import React, { useCallback, useState } from 'react';

interface Method {
	name: string;
	description?: string;
	command?: string;
	link?: { url: string; text: string };
	steps?: string[];
}

interface PrerequisiteItem {
	name: string;
	description?: string;
	command?: string;
	link?: { url: string; text: string };
	methods?: Method[];
}

interface PrerequisitesProps {
	items: PrerequisiteItem[];
}

function CopyButton({ text }: { text: string }) {
	const [copied, setCopied] = useState(false);

	const handleCopy = useCallback(async () => {
		await navigator.clipboard.writeText(text);
		setCopied(true);
		setTimeout(() => setCopied(false), 2000);
	}, [text]);

	return (
		<button
			onClick={handleCopy}
			className="absolute right-2 top-2 p-2 rounded-md bg-fd-muted/80 hover:bg-fd-muted text-fd-muted-foreground hover:text-fd-foreground transition-all duration-200"
			title={copied ? 'Copied!' : 'Copy to clipboard'}
		>
			{copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
		</button>
	);
}

function CommandBlock({ command }: { command: string }) {
	return (
		<div className="relative group">
			<pre className="bg-fd-muted/50 dark:bg-fd-muted rounded-xl p-4 pr-12 overflow-x-auto m-0 border border-fd-border">
				<code className="text-sm font-mono text-fd-foreground">{command}</code>
			</pre>
			<CopyButton text={command} />
		</div>
	);
}

export default function Prerequisites({ items }: PrerequisitesProps) {
	const [selectedMethods, setSelectedMethods] = useState<Record<number, number>>({});

	const handleMethodChange = (itemIndex: number, methodIndex: number) => {
		setSelectedMethods((prev) => ({
			...prev,
			[itemIndex]: methodIndex,
		}));
	};

	return (
		<div className="grid gap-4 my-6">
			{items.map((item, index) => (
				<div
					key={index}
					className="group relative overflow-hidden rounded-2xl border border-fd-border bg-fd-card transition-all duration-300 hover:border-pink-300 dark:hover:border-pink-800 hover:shadow-lg hover:shadow-pink-500/5"
				>
					{/* Gradient accent on hover */}
					<div className="absolute inset-0 bg-gradient-to-br from-pink-500/5 to-purple-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />

					<div className="relative p-6">
						{/* Header */}
						<div className="flex justify-between items-start mb-4 flex-wrap gap-3">
							<h4 className="m-0 text-lg font-semibold text-fd-foreground flex items-center gap-2">
								{item.name}
							</h4>
							{item.link && (
								<a
									href={item.link.url}
									target="_blank"
									rel="noopener noreferrer"
									className="inline-flex items-center gap-1.5 text-sm font-medium text-pink-600 dark:text-pink-400 bg-pink-500/10 px-3 py-1.5 rounded-full border border-pink-500/20 hover:bg-pink-500/20 transition-colors no-underline"
								>
									{item.link.text}
									<ExternalLink className="h-3.5 w-3.5" />
								</a>
							)}
						</div>

						{/* Description */}
						{item.description && (
							<p className="m-0 mb-4 text-fd-muted-foreground text-sm leading-relaxed">
								{item.description}
							</p>
						)}

						{/* Single installation method */}
						{item.command && !item.methods && (
							<div className="mt-4">
								<span className="block text-xs font-semibold text-fd-muted-foreground uppercase tracking-wider mb-2">
									Quick install
								</span>
								<CommandBlock command={item.command} />
							</div>
						)}

						{/* Multiple installation methods */}
						{item.methods && (
							<div className="mt-4">
								{/* Tabs */}
								<div className="flex gap-1 p-1 bg-fd-muted/50 rounded-xl mb-4">
									{item.methods.map((method, methodIndex) => (
										<button
											key={methodIndex}
											className={cn(
												'flex-1 px-4 py-2 text-sm font-medium rounded-lg transition-all duration-200',
												(selectedMethods[index] || 0) === methodIndex
													? 'bg-fd-background text-fd-foreground shadow-sm'
													: 'text-fd-muted-foreground hover:text-fd-foreground hover:bg-fd-background/50',
											)}
											onClick={() => handleMethodChange(index, methodIndex)}
										>
											{method.name}
										</button>
									))}
								</div>

								{/* Tab content */}
								<div className="animate-fade-in">
									{item.methods[selectedMethods[index] || 0] && (
										<>
											{item.methods[selectedMethods[index] || 0].description && (
												<p className="m-0 mb-3 text-fd-muted-foreground text-sm">
													{item.methods[selectedMethods[index] || 0].description}
												</p>
											)}

											{item.methods[selectedMethods[index] || 0].command && (
												<CommandBlock
													command={item.methods[selectedMethods[index] || 0].command!}
												/>
											)}

											{item.methods[selectedMethods[index] || 0].link && (
												<div className="mt-4">
													<a
														href={item.methods[selectedMethods[index] || 0].link!.url}
														target="_blank"
														rel="noopener noreferrer"
														className="btn-primary inline-flex items-center gap-2 no-underline"
													>
														{item.methods[selectedMethods[index] || 0].link!.text}
														<ExternalLink className="h-4 w-4" />
													</a>
												</div>
											)}

											{item.methods[selectedMethods[index] || 0].steps && (
												<ol className="mt-4 space-y-2 m-0 list-none pl-0">
													{item.methods[selectedMethods[index] || 0].steps!.map(
														(step, stepIndex) => (
															<li
																key={stepIndex}
																className="flex items-start gap-3 text-fd-muted-foreground text-sm leading-relaxed"
															>
																<span className="flex-shrink-0 w-6 h-6 rounded-full bg-pink-500/10 text-pink-600 dark:text-pink-400 flex items-center justify-center text-xs font-semibold">
																	{stepIndex + 1}
																</span>
																{step}
															</li>
														),
													)}
												</ol>
											)}
										</>
									)}
								</div>
							</div>
						)}
					</div>
				</div>
			))}
		</div>
	);
}
