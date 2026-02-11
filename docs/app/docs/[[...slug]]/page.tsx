import defaultMdxComponents from 'fumadocs-ui/mdx';
import { DocsBody, DocsPage } from 'fumadocs-ui/page';
import { notFound } from 'next/navigation';

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
import { source } from '@/lib/source';

export default async function Page(props: { params: Promise<{ slug?: string[] }> }) {
	const params = await props.params;
	const page = source.getPage(params.slug);
	if (!page) notFound();

	const MDX = page.data.body;

	const _showDescription = page.data.description && page.data.description !== page.data.title;

	return (
		<DocsPage toc={page.data.toc} full={page.data.full}>
			<DocsBody>
				<MDX
					components={{
						...defaultMdxComponents,
						Info,
						Note,
						Warning,
						Tip,
						Example,
						Construction,
						Prerequisites,
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
					}}
				/>
			</DocsBody>
		</DocsPage>
	);
}

export async function generateStaticParams() {
	return source.generateParams();
}

export async function generateMetadata(props: { params: Promise<{ slug?: string[] }> }) {
	const params = await props.params;
	const page = source.getPage(params.slug);
	if (!page) notFound();

	return {
		title: page.data.title,
		description: page.data.description,
	};
}
