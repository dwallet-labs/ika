import { source } from '@/lib/source';
import { createFromSource } from 'fumadocs-core/search/server';

export const revalidate = false;

const search = createFromSource(source);

export const { staticGET: GET } = search;
