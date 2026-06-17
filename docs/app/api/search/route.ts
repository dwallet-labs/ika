import { createFromSource } from 'fumadocs-core/search/server';

import { source } from '@/lib/source';

export const revalidate = false;

const search = createFromSource(source);

export const { staticGET: GET } = search;
