'use client';

import { createStore, del, get, set } from 'idb-keyval';

const store = createStore('ikavery-solana', 'vault-state');

export function idbGet<T>(key: string): Promise<T | undefined> {
	return get<T>(key, store);
}

export function idbSet<T>(key: string, value: T): Promise<void> {
	return set(key, value, store);
}

export function idbDel(key: string): Promise<void> {
	return del(key, store);
}
