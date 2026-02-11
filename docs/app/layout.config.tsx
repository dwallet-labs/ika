import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import Image from 'next/image';

export const baseOptions: BaseLayoutProps = {
	nav: {
		title: (
			<div className="flex items-center gap-2">
				<Image
					src="/icon-white.png"
					alt="Ika Logo"
					width={24}
					height={24}
					className="dark:invert-0 invert"
				/>
				<span className="font-semibold">Ika Docs</span>
			</div>
		),
	},
	links: [
		{
			text: 'GitHub',
			url: 'https://github.com/dwallet-labs/ika',
			external: true,
		},
	],
};
