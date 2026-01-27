# Ika Documentation

This documentation site is built using [Fumadocs](https://fumadocs.dev/), a modern Next.js-based documentation framework.

## Installation

```bash
npm install
```

## Local Development

```bash
npm run dev
```

This starts a local development server at `http://localhost:3000`. Changes are reflected live.

## Build

```bash
npm run build
```

This generates an optimized production build in the `.next` directory.

## Preview Production Build

```bash
npm run start
```

## Project Structure

```
docs/
├── app/                    # Next.js app directory
│   ├── docs/              # Documentation pages
│   ├── api/search/        # Search API
│   └── layout.tsx         # Root layout
├── content/docs/          # MDX documentation content
│   ├── sdk/              # SDK documentation
│   ├── move-integration/ # Move integration docs
│   ├── core-concepts/    # Core concepts
│   ├── operators/        # Operator guides
│   └── code-examples/    # Code examples
├── components/            # React components
├── lib/                   # Utilities and source config
└── public/               # Static assets
```

## Deployment

Deploy to any platform that supports Next.js:

- **Vercel**: Connect your repository for automatic deployments
- **Static Export**: Run `npm run build` with `output: 'export'` in next.config.mjs
