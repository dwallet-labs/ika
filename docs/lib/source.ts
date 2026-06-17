import { loader } from 'fumadocs-core/source';
import {
	BookOpen,
	Bot,
	Code2,
	Globe,
	Library,
	Server,
	Zap,
	type LucideIcon,
} from 'lucide-react';
import { createElement } from 'react';

import { docs } from '@/.source';

// Lucide icons keyed by the string referenced in each section's meta.json
// `icon` field. Top-level docs folders pick one of these to render in the
// sidebar.
const icons: Record<string, LucideIcon> = {
	BookOpen,
	Bot,
	Code2,
	Globe,
	Library,
	Server,
	Zap,
};

export const source = loader({
	baseUrl: '/docs',
	source: docs.toFumadocsSource(),
	icon(name) {
		if (!name) return undefined;
		const Icon = icons[name];
		if (!Icon) return undefined;
		return createElement(Icon, { className: 'size-4' });
	},
});
