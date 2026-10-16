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
	/** Moves `sessions` to the present time on `kernel`'s clock, and `delegations` too unless kept; neither moves back. Complete when every follower finished all its work, none left for later. */
	record(
		subject: string,
		options?: { readonly keepDelegations?: boolean },
	): Promise<{ readonly complete: boolean }>;
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
	/** Called once the boundary is written; whether `delegations` stayed where it was. Fails when it leaves any work for later. */
	follow(subject: string, revocation: { readonly keepDelegations: boolean }): Promise<void>;
}

export const revocationFollowers = extensionPoint<RevocationFollower>(
	"subject-revocation.followers",
	{ multiplicity: "keyed", keyOf: (follower) => follower.name },
);
export * from "./store.ts";
