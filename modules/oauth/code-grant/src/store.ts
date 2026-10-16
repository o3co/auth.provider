import { contract } from "@mod/kernel";

declare const stored: unique symbol;
/** A code's record as the store keeps it: the store never reads it, and only code-grant opens it. */
export type StoredCode = { readonly [stored]: true };

/** A record as a change leaves it, and its new lifetime from the write; without one it stays. */
export interface ChangedCode {
	readonly value: StoredCode;
	readonly lifetimeMs?: number;
}

/** Where codes are kept, by a name made from the code. Every call throws Unavailable when the place cannot tell. */
export interface CodeStore {
	/** A code's name: never the code, which cannot be had from it; names are kept, so it never changes. */
	nameOf(code: string): string;
	/** Keeps a new code's record for its lifetime, unless the name holds one already. */
	save(name: string, record: StoredCode, lifetimeMs: number): Promise<"created" | "exists">;
	/**
	 * Changes the record from what it holds, answering it before and after; `change` runs again on
	 * a race, so it is pure, and the caller judges what the change did. Nothing when gone.
	 */
	update(
		name: string,
		change: (record: StoredCode) => ChangedCode | undefined,
	): Promise<{ readonly before: StoredCode; readonly after: StoredCode } | undefined>;
}

/** The codes whose tokens must still be revoked, kept until done. */
export interface VoidList {
	add(name: string): Promise<void>;
	done(name: string): Promise<void>;
	/** Hands each listed code's name to `handle`; a code whose handling fails stays, and is counted. */
	each(handle: (name: string) => Promise<void>): Promise<{ readonly failed: number }>;
}

export const codeStore = contract<CodeStore>("code-grant.code-store");
export const voidList = contract<VoidList>("code-grant.void-list");

/**
 * What the places must hold to: a used code that came back would be usable twice, and a code or
 * listed void that was lost would leave its token alive.
 */
export const codeStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	namesFromSecret: true,
} as const;
