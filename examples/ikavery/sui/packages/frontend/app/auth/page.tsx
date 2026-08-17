'use client';

import { Loader2 } from 'lucide-react';

/**
 * Enoki OAuth callback page. The popup window lands here after Google /
 * Twitch / Facebook redirects back. The EnokiWallet adapter (registered in
 * RootLayout via DappKitProviders) detects the URL fragment, posts the
 * result to the opener window, and closes this popup — no code in this
 * file actively does anything besides render a placeholder.
 */
export default function AuthCallback() {
	return (
		<div className="min-h-screen flex items-center justify-center">
			<div className="flex flex-col items-center gap-3 text-center">
				<Loader2 className="h-6 w-6 text-clay animate-spin" />
				<span className="smallcaps text-text-2">Finishing sign-in…</span>
				<span className="text-[12.5px] text-text-3 max-w-[280px] leading-[1.55]">
					You can close this window if it doesn&apos;t close on its own.
				</span>
			</div>
		</div>
	);
}
