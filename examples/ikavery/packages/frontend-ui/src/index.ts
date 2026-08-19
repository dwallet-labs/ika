// Lib

// Bento grid
export { Tile, TileEyebrow, TileTitle } from './components/bento';
// Disclaimer modal
export {
	type DisclaimerClause,
	DisclaimerModal,
	type DisclaimerModalProps,
} from './components/disclaimer-modal';
// Motion
export { CountUp, CursorSpotlight, Reveal, StaggerOnView, TypeIn } from './components/motion';
// Layout / shell
export {
	Shell,
	ShellFooter,
	type ShellFooterProps,
	ShellHeader,
	type ShellHeaderProps,
} from './components/shell';
// Skeleton placeholders
export {
	ProposalCardSkeleton,
	ProposalDetailSkeleton,
	Skeleton,
	SkeletonLine,
} from './components/skeleton';
// UI primitives
export { Button, type ButtonProps, buttonVariants } from './components/ui/button';
export {
	Card,
	CardContent,
	CardEyebrow,
	CardFooter,
	CardHeader,
	CardTitle,
} from './components/ui/card';
// Threshold dial (landing-page demo)
export { VaultDial } from './components/vault-dial';
export { cn } from './lib/cn';
export { bytesToHex, hexToBytes, truncateAddress } from './lib/format';
