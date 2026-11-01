import { contract } from "@mod/kernel";

declare const family: unique symbol;
/** A family's record as the store keeps it: the store never reads it, and only refresh opens it. */
export type StoredFamily = { readonly [family]: true };
declare const redemption: unique symbol;
/** What a code's redemption left, as the store keeps it; only refresh opens it. */
export type StoredRedemption = { readonly [redemption]: true };

declare const link: unique symbol;
/** The family an access token came from, as the store keeps it; only refresh opens it. */
export type StoredLink = { readonly [link]: true };

/** A record as a change leaves it, and its new lifetime from the write; without one it stays. */
export interface ChangedFamily {
	readonly value: StoredFamily;
	readonly lifetimeMs?: number;
}

/** Where families are kept, by name. Every call throws Unavailable when the place cannot tell. */
export interface FamilyStore {
	/** Keeps a new family's record for its lifetime, unless the name holds one already. */
	save(id: string, record: StoredFamily, lifetimeMs: number): Promise<"created" | "exists">;
	read(id: string): Promise<StoredFamily | undefined>;
	/** Changes the record from what it holds; `change` reruns on a race, so it is pure. Nothing when gone. */
	update(
		id: string,
		change: (record: StoredFamily) => ChangedFamily | undefined,
	): Promise<{ readonly before: StoredFamily; readonly after: StoredFamily } | undefined>;
}

export interface RedemptionStore {
	save(
		redemption: string,
		record: StoredRedemption,
		lifetimeMs: number,
	): Promise<"created" | "exists">;
	read(redemption: string): Promise<StoredRedemption | undefined>;
}

/** The family of each access token, by token id; ids are not secrets. */
export interface TokenFamilies {
	save(tokenId: string, record: StoredLink, lifetimeMs: number): Promise<"created" | "exists">;
	read(tokenId: string): Promise<StoredLink | undefined>;
}

/**
 * Members by key, each for its own lifetime, which only lengthens; past a cap, the first to end is
 * pushed out, and awaits under its key until it is said settled.
 */
export interface MemberLists {
	add(
		key: string,
		member: string,
		lifetimeMs: number,
	): Promise<{ readonly pushedOut: readonly string[] }>;
	members(
		key: string,
	): Promise<readonly { readonly member: string; readonly remainingMs: number }[]>;
	/** The members pushed out under the key and not yet settled, within their lifetimes. */
	awaiting(key: string): Promise<readonly string[]>;
	settled(key: string, member: string): Promise<void>;
}

/** The families whose revocation must still be finished, kept until done. */
export interface SettleList {
	add(id: string): Promise<void>;
	done(id: string): Promise<void>;
	/** Hands each listed family to `handle`; one whose handling fails stays, and is counted. */
	each(handle: (id: string) => Promise<void>): Promise<{ readonly failed: number }>;
}

export const familyStore = contract<FamilyStore>("refresh.family-store");
export const redemptionStore = contract<RedemptionStore>("refresh.redemption-store");
/** The families each session started, so closing it revokes them. */
export const sessionFamilies = contract<MemberLists>("refresh.session-families");
/** The access tokens each family issued, by `tokens`' references, so revoking it revokes them. */
export const issuedAccess = contract<MemberLists>("refresh.issued-access");
export const tokenFamilies = contract<TokenFamilies>("refresh.token-families");
export const settleList = contract<SettleList>("refresh.settle-list");

/** A family or mark that was lost would let a spent token or code be used again, or leave tokens alive. */
export const refreshStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
