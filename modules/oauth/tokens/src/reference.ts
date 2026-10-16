/** Names an issued token for `revokeReferenced`, so it can be revoked later without the token. */
export function referenceOf(issued: { readonly id: string; readonly expiresAt: number }): string {
	return `${issued.id}|${issued.expiresAt}`;
}

/** What a reference names; nothing for a string that is not one. */
export function namedBy(reference: string) {
	const [, id, at] = /^([A-Za-z0-9_-]+)\|(\d+)$/.exec(reference) ?? [];
	return id && at ? { id, expiresAt: Number(at) } : undefined;
}
