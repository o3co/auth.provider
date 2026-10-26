import type { Checked } from "../assertion/assertion.ts";
import { meets } from "../conditions/conditions.ts";
import type { IssuerEntry } from "../issuers/issuers.ts";

/** An assertion `check` found valid. */
export type Verified = Extract<Checked, { readonly kind: "valid" }>;

/** What identifying found, handed back unread to the grant's `handle`: the assertion and its subject. */
export interface Identified {
	readonly verified: Verified;
	readonly subject: string;
}

/**
 * The one answer to a request naming no client before its subject is taken: it tells nothing of
 * which issuers take such a request, of their conditions, nor of whom their signers stand for.
 */
export const unidentified = Object.freeze({
	kind: "error",
	error: "invalid_grant",
	description: "untrusted signer",
} as const);

/** What this module made, so `identifiedOf` reads back no look-alike. */
const made = new WeakSet<object>();

/** What identifying handed back, as this module made it; none for anything else. */
export const identifiedOf = (value: unknown): Identified | undefined =>
	typeof value === "object" && value !== null && made.has(value)
		? (value as Identified)
		: undefined;

/**
 * The client an assertion identifies for a request naming none: its entry's `client`, once its
 * claims meet the entry's conditions and its subject is taken. Any failure is `unidentified`; a
 * subject that cannot be told throws, as `subjectOf` does.
 */
export async function identifiedBy(
	checked: Checked,
	entryOf: (issuer: string) => IssuerEntry | undefined,
	subjectOf: (entry: string, sub: string) => Promise<string | undefined>,
): Promise<
	| { readonly kind: "client"; readonly client: string; readonly identified: Identified }
	| typeof unidentified
> {
	if (checked.kind !== "valid") return unidentified;
	const entry = entryOf(checked.entry);
	if (entry?.client === undefined) return unidentified;
	if (entry.conditions && !meets(entry.conditions, checked.claims)) return unidentified;
	const subject = await subjectOf(checked.entry, checked.subject);
	if (subject === undefined) return unidentified;
	const identified: Identified = Object.freeze({ verified: checked, subject });
	made.add(identified);
	return { kind: "client", client: entry.client, identified };
}

/**
 * An entry and its client, bound both ways: an entry with a client issues to it alone, and an
 * entry's client takes its own entry's assertions alone, a delegated issuer's none.
 */
export function bindingOf(entries: readonly IssuerEntry[]) {
	const bound = new Set(entries.flatMap((e) => (e.client === undefined ? [] : [e.client])));
	return {
		/** Whether the assertion of `entry` (none for a delegated issuer's) is for another client than `client`. */
		forAnother: (entry: IssuerEntry | undefined, client: string): boolean => {
			const own = entry?.client;
			return own === undefined ? bound.has(client) : own !== client;
		},
	};
}
