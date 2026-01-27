import type { MDXComponents } from 'mdx/types';
import defaultComponents from 'fumadocs-ui/mdx';
import { Callout } from 'fumadocs-ui/components/callout';
import { Info, Note, Warning, Tip, Example, Construction } from '@/components/InfoBox';
import Prerequisites from '@/components/Prerequisites';
import ArchitectureDiagram, {
  ArchitectureOverviewDiagram,
  ProtocolLifecycleDiagram,
  PresignLifecycleDiagram,
  KeyImportDiagram,
  FutureSigningDiagram,
  CapabilityLifecycleDiagram,
  SigningFlowDiagram,
  MultisigFlowDiagram,
  SharedDWalletFlowDiagram,
} from '@/components/ArchitectureDiagram';

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
