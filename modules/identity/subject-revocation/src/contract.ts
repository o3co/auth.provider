import { contract, extensionPoint } from "@mod/kernel";

export interface SubjectRevocation {
	/** `record(subject)`. */
	revoke(subject: string): Promise<void>;
	/** `compare(subject, authenticatedAt, "sessions")`, `authenticatedAt` in epoch milliseconds. */
	check(subject: string, authenticatedAt: number): Promise<"valid" | "revoked">;
}

export const subjectRevocation = contract<SubjectRevocation>("subject-revocation");

/** `sessions` ends authentications; `delegations` ends upstream credentials held for clients. */
export type BoundaryKind = "sessions" | "delegations";

export interface Revocations {
	/**
	 * Moves `sessions` to the present time on `kernel`'s clock, and `delegations` too unless kept;
	 * neither moves back. Complete when every follower finished all its work, none left for later;
	 * `erased` where the record the write read carried a mark of erasure, the key absent otherwise.
	 */
	record(
		subject: string,
		options?: { readonly keepDelegations?: boolean },
	): Promise<{ readonly complete: boolean; readonly erased?: true }>;
	/** Whether something of the subject started at `time` (epoch ms) is still valid against the kind's boundary, widened by `allowanceMs` (none by default). */
	compare(
		subject: string,
		time: number,
		kind: BoundaryKind,
		allowanceMs?: number,
	): Promise<"valid" | "revoked">;
}

export const revocations = contract<Revocations>("subject-revocation.revocations");

/** Work that follows a recorded revocation, contributed by the module that owns it. */
export interface RevocationFollower {
	readonly name: string;
	/**
	 * Called once the boundary is written; whether `delegations` stayed where it was, and `erased`
	 * as `record` answers it. Fails when it leaves any work for later.
	 */
	follow(
		subject: string,
		revocation: { readonly keepDelegations: boolean; readonly erased?: true },
	): Promise<void>;
}

export const revocationFollowers = extensionPoint<RevocationFollower>(
	"subject-revocation.followers",
	{ multiplicity: "keyed", keyOf: (follower) => follower.name },
);
/** Marking a subject erased, for good: every comparison of its boundaries answers revoked from then. */
export interface SubjectErasure {
	/**
	 * Marks the subject erased by a confirmed write at its deadline, the boundaries kept as they
	 * are; a subject marked already keeps its first mark, which is answered.
	 */
	markErased(subject: string): Promise<{ readonly kind: "marked"; readonly erasedAt: number }>;
}

/** Taken by no module until account erasure, which alone marks a subject erased, is named. */
export const subjectErasure = contract<SubjectErasure>("subject-revocation.erasure", {
	takenBy: [],
});
/** The fence a bundle of credentials passes before it is answered, one write per bundle. */
export interface ErasureFence {
	/**
	 * Passes where the subject is not erased, keeping a receipt under `receiptId` held by its
	 * boundary as read, so a mark of erasure written meanwhile makes it read again; `erased` where
	 * the subject is, and nothing is written. Where erasure is off, passes without writing. A
	 * `receiptId` already holding a receipt is thrown, never passed: each fence's is new.
	 */
	fence(subject: string, receiptId: string): Promise<"passed" | "erased">;
}

export const erasureFence = contract<ErasureFence>("subject-revocation.erasure-fence");

/** A module's statement that, on this boundary, it checks access tokens and fences their issuance. */
export interface ErasureGuard {
	readonly name: string;
}

/** Where erasure is enabled, a composition must hold one at least, and a boundary store that fences. */
export const erasureGuards = extensionPoint<ErasureGuard>("subject-revocation.erasure-guards", {
	multiplicity: "many",
});
export * from "./store.ts";
