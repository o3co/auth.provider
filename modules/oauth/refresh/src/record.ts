import { createHash } from "node:crypto";
import type { Binding } from "@mod/sender-binding";
import { z } from "zod";
import type { StoredFamily, StoredLink, StoredRedemption } from "./store.ts";

export interface Family {
	/** The record's format; one of format 1 is read too, its authentication time known. */
	readonly format: 2;
	/** The hash of the one secret that may be used next. */
	readonly current: string;
	readonly clientId: string;
	readonly subject: string;
	readonly scope: readonly string[];
	readonly audience: readonly string[];
	readonly session?: string;
	/** On `kernel`'s clock, epoch ms. */
	readonly authenticatedAt: number;
	/** The authentication time is not known, so no access token of the family states one. */
	readonly authenticatedAtUnknown?: true;
	readonly amr: readonly string[];
	/** The acr the family's first authentication met, when it met one. */
	readonly acr?: string;
	readonly binding?: Binding;
	/** On `kernel`'s clock, epoch ms. */
	readonly expiresAt: number;
}

/** A revoked family keeps nothing else, so nothing can bring it back; its format stays 1, read by hosts either side. */
export type Kept = Family | { readonly format: 1; readonly revoked: true };
/** The family a redemption started, or a mark that it may start none. */
export type Redemption =
	| { readonly format: 1; readonly family: string }
	| { readonly format: 1; readonly taken: true };

const strings = z.array(z.string());
const familyShapeBefore = z.strictObject({
	format: z.literal(1),
	current: z.string(),
	clientId: z.string(),
	subject: z.string(),
	scope: strings,
	audience: strings,
	session: z.string().optional(),
	authenticatedAt: z.number(),
	amr: strings,
	acr: z.string().min(1).optional(),
	binding: z
		.strictObject({ member: z.string(), confirmation: z.string(), tokenType: z.string() })
		.optional(),
	expiresAt: z.number(),
});
const familyShape = familyShapeBefore.extend({
	format: z.literal(2),
	authenticatedAtUnknown: z.literal(true).optional(),
});
const keptShape = z.union([
	familyShape,
	familyShapeBefore,
	z.strictObject({ format: z.literal(1), revoked: z.literal(true) }),
]);
const linkShape = z.strictObject({ format: z.literal(1), family: z.string() });
const redemptionShape = z.union([
	linkShape,
	z.strictObject({ format: z.literal(1), taken: z.literal(true) }),
]);

/** Records outlive what they cover by this much, for hosts whose clocks lag. */
export const allowanceMs = 120_000;

export const toStored = (kept: Kept) => kept as unknown as StoredFamily;
/** What a family's record holds, checked on every read; nothing for a format or shape this does not know. */
export const fromStored = (stored: StoredFamily | undefined): Kept | undefined => {
	const read = keptShape.safeParse(stored);
	if (!read.success) return undefined;
	return "current" in read.data ? ({ ...read.data, format: 2 } as Family) : read.data;
};
export const liveOf = (kept: Kept | undefined) => (kept && "current" in kept ? kept : undefined);
export const liveFamily = (stored: StoredFamily | undefined) => liveOf(fromStored(stored));
export const toStoredRedemption = (left: Redemption) => left as unknown as StoredRedemption;
export const fromStoredRedemption = (stored: StoredRedemption): Redemption | undefined => {
	const read = redemptionShape.safeParse(stored);
	return read.success ? (read.data as Redemption) : undefined;
};
/** The family an access token came from. */
export type Link = z.output<typeof linkShape>;
export const toStoredLink = (link: Link) => link as unknown as StoredLink;
export const fromStoredLink = (stored: StoredLink): Link | undefined => {
	const read = linkShape.safeParse(stored);
	return read.success ? read.data : undefined;
};

export const hashOf = (secret: string) => createHash("sha256").update(secret).digest("base64url");

/** `family.secret`: the family names where to look, the secret proves the holder. */
const tokenPattern = /^([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/;
export function parseToken(token: string) {
	const [, id, secret] = tokenPattern.exec(token) ?? [];
	return id && secret ? { id, secret } : undefined;
}
