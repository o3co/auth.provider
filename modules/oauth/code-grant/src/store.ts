import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { contract } from "@mod/kernel";
import { lifetimeSecondsRange } from "@mod/tokens";

declare const stored: unique symbol;
/** A code's record as the store keeps it: the store never reads it, and only code-grant opens it. */
export type StoredCode = { readonly [stored]: true };

/** A record as a change leaves it; it keeps its end. */
export interface ChangedCode {
	readonly value: StoredCode;
}

/** Where codes are kept, by a name made from the code. Every call throws Unavailable when the place cannot tell. */
export interface CodeStore {
	/** A code's name: never the code, which cannot be had from it; names are kept, so it never changes. */
	nameOf(code: string): string;
	/**
	 * Keeps a new code's record, under the code's name (`nameOf`), for its lifetime and its subject,
	 * unless the name holds one already (`exists`) or, where the Store fences saves past a subject's
	 * erasure, the subject is erased there (`erased`). It takes the code itself, so a Store keyed by
	 * secrets names it; every other call takes the name. The subject comes last.
	 */
	save(
		code: string,
		record: StoredCode,
		lifetimeMs: number,
		subject: string,
	): Promise<"created" | "exists" | "erased">;
	/**
	 * Changes the record from what it holds, answering it before and after; `change` runs again on
	 * a race, so it is pure, and the caller judges what the change did. Nothing when gone.
	 */
	update(
		name: string,
		change: (record: StoredCode) => ChangedCode | undefined,
	): Promise<{ readonly before: StoredCode; readonly after: StoredCode } | undefined>;
	/**
	 * Erases a subject's codes here, where the Store can: optional in 0.20, required in 0.22. With
	 * the redemption records' ports, all four or none.
	 */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/** Once, under the maintenance key; optional as `erase` is. */
	migrate?(walk: Walk, reading: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
}

declare const redemptionRecord: unique symbol;
/** A redemption's record as the store keeps it: its token's reference and void mark; only code-grant opens it. */
export type StoredRedemptionRecord = { readonly [redemptionRecord]: true };

/** A redemption's record as a change leaves it; it keeps its end. */
export interface ChangedRedemptionRecord {
	readonly value: StoredRedemptionRecord;
}

/**
 * Each redemption's record, by the redemption's name (`redemptionOf`): what its token was, and
 * whether a reuse voided it. Every call throws Unavailable when the place cannot tell.
 */
export interface RedemptionRecords {
	/**
	 * Keeps a redemption's record for its lifetime and its subject, unless the name holds one
	 * (`exists`) or, where the Store fences a subject's erasure, the subject is erased (`erased`).
	 */
	create(
		name: string,
		record: StoredRedemptionRecord,
		lifetimeMs: number,
		subject: string,
	): Promise<"created" | "exists" | "erased">;
	read(name: string): Promise<StoredRedemptionRecord | undefined>;
	/** Changes the record from what it holds; `change` reruns on a race, so it is pure. Nothing when gone. */
	update(
		name: string,
		change: (record: StoredRedemptionRecord) => ChangedRedemptionRecord | undefined,
	): Promise<
		{ readonly before: StoredRedemptionRecord; readonly after: StoredRedemptionRecord } | undefined
	>;
	/** Erases a subject's redemption records here, where the Store can; optional as the codes' is. */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/** Once, under the maintenance key; optional as `erase` is. */
	migrate?(walk: Walk, reading: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
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
export const redemptionRecords = contract<RedemptionRecords>("code-grant.redemption-records");

/**
 * What the places must hold to: a used code that came back would be usable twice, and a code,
 * a redemption's record or a listed void that was lost would leave its token alive. The
 * redemption records hold to these too, their names a digest of the code.
 */
export const codeStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	namesFromSecret: true,
} as const;

/**
 * The longest a redemption's record is kept: the longest an access token may live (`tokens`'
 * `lifetimeSecondsRange.max`), records' allowance after its end, and as much again for the time
 * between the code's use-up and the token's issue. A Store bounding redemption records declares it,
 * and one bounding codes: no code lives longer, one a 0.19 instance kept to its token's end and
 * records' allowance included.
 * TODO(0.22): codes are bounded by `code-lifetime`'s longest, once no 0.19 record is left.
 */
export const redemptionRecordMaxMs = lifetimeSecondsRange.max * 1000 + 2 * 120_000;
