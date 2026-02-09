import "@/styles/globals.css";
import type { AppProps } from "next/app";
import Head from "next/head";

export default function App({ Component, pageProps }: AppProps) {
  return (
    <>
      <Head>
        <title>KeySpring | Cross-Chain Wallet Demo</title>
        <meta
          name="description"
          content="Create an Ethereum wallet from any browser wallet. Send ETH on Base Sepolia — non-custodially powered by Ika."
        />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="theme-color" content="#0a0a0f" />
        <link rel="icon" href="/favicon.ico" />

        {/* Open Graph */}
        <meta property="og:type" content="website" />
        <meta property="og:title" content="KeySpring | Cross-Chain Wallet Demo" />
        <meta
          property="og:description"
          content="Create an Ethereum wallet from any browser wallet. Send ETH on Base Sepolia — non-custodially powered by Ika."
        />
        <meta property="og:site_name" content="KeySpring" />

        {/* Twitter */}
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content="KeySpring | Cross-Chain Wallet Demo" />
        <meta
          name="twitter:description"
          content="Create an Ethereum wallet from any browser wallet. Send ETH on Base Sepolia — non-custodially powered by Ika."
        />
      </Head>
      <Component {...pageProps} />
    </>
  );
}
