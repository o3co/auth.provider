import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { contract } from "@mod/kernel";

declare const stored: unique symbol;
/** A held login as the store keeps it: the store never reads it, and only this package opens it. */
export type StoredHeldLogin = { readonly [stored]: true };

/** Where held logins are kept, by their carry, never kept in clear. Every call throws Unavailable when the place cannot tell. */
export interface HeldLoginStore {
	/**
	 * Keeps a new record for its lifetime and its subject, unless the carry holds one already
	 * (`exists`) or, where the Store fences saves past a subject's erasure, the subject is erased
	 * there (`erased`). The subject comes last: keep this value, this long, for this subject.
	 */
	save(
		carry: string,
		record: StoredHeldLogin,
		lifetimeMs: number,
		subject: string,
	): Promise<"created" | "exists" | "erased">;
	/** Changes the record from what it holds; `change` reruns on a race, so it is pure. Nothing when gone. */
	update(
		carry: string,
		change: (record: StoredHeldLogin) => { readonly value: StoredHeldLogin } | undefined,
	): Promise<{ readonly before: StoredHeldLogin; readonly after: StoredHeldLogin } | undefined>;
	/** Removes the record under the carry; what a Store answers, if anything, is not read. */
	remove(carry: string): Promise<unknown>;
	/**
	 * Erases a subject's held logins here, where the Store can: optional in 0.20, required in 0.22,
	 * as a Store not built through `subject-records` cannot be erased.
	 */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/** Once, under the maintenance key, as `subject-records`' migration does; optional as `erase` is. */
	migrate?(walk: Walk, subjectOf: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
}

/** The longest a held login is kept (federation's `transaction-lifetime` at most): a Store fencing held logins by a bound declares it. */
export const heldLoginLifetimeMaxMs = 3_600_000;

export const heldLoginStore = contract<HeldLoginStore>("upstream-handoff.held-login-store");

/** A taken held login back after a failover could hand its tokens over twice. */
export const heldLoginStoreNeeds = {
	survivesFailover: true,
	/** Names derive from the carry, so the place never keeps it in clear. */
	namesFromSecret: true,
} as const;
