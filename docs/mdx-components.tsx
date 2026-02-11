import { Callout } from 'fumadocs-ui/components/callout';
import defaultComponents from 'fumadocs-ui/mdx';
import type { MDXComponents } from 'mdx/types';

import ArchitectureDiagram, {
	ArchitectureOverviewDiagram,
	CapabilityLifecycleDiagram,
	FutureSigningDiagram,
	KeyImportDiagram,
	MultisigFlowDiagram,
	PresignLifecycleDiagram,
	ProtocolLifecycleDiagram,
	SharedDWalletFlowDiagram,
	SigningFlowDiagram,
} from '@/components/ArchitectureDiagram';
import { Construction, Example, Info, Note, Tip, Warning } from '@/components/InfoBox';
import Prerequisites from '@/components/Prerequisites';

export function useMDXComponents(components: MDXComponents): MDXComponents {
	return {
		...defaultComponents,
		...components,
		Callout,
		Info,
		Note,
		Warning,
		Tip,
		Example,
		Construction,
		Prerequisites,
		// Architecture diagrams
		ArchitectureDiagram,
		ArchitectureOverviewDiagram,
		ProtocolLifecycleDiagram,
		PresignLifecycleDiagram,
		KeyImportDiagram,
		FutureSigningDiagram,
		CapabilityLifecycleDiagram,
		SigningFlowDiagram,
		MultisigFlowDiagram,
		SharedDWalletFlowDiagram,
	};
}
