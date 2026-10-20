import { contract, extensionPoint } from "@mod/kernel";
import type { Binding, TokenValidity } from "@mod/sender-binding";

/** Who acts for the subject, and the actor it acts for in turn (`act`). */
export interface Actor {
	readonly subject: string;
	readonly actor?: Actor;
}

/** `actor`, `amr` and `authenticatedAt` are written only when given. */
export interface AccessGrant {
	readonly subject: string;
	readonly issuedTo: string;
	readonly audience: readonly string[];
	readonly scope: readonly string[];
	readonly actor?: Actor;
	readonly amr?: readonly string[];
	/** Epoch ms, kept to the second, and never after the token's issue. */
	readonly authenticatedAt?: number;
	/** The authentication time is not known: no `auth_time` is written, whatever `authenticatedAt` holds. */
	readonly authenticatedAtUnknown?: true;
	readonly acr?: string;
}

export interface IssuedAccess {
	readonly token: string;
	readonly id: string;
	/** Epoch ms. */
	readonly expiresAt: number;
	readonly expiresIn: number;
	readonly tokenType: string;
}

export type AccessCheck =
	| {
			readonly kind: "valid";
			/** The id `issue` answered. */
			readonly id: string;
			readonly grant: AccessGrant;
			readonly expiresAt: number;
			readonly tokenType: string;
			readonly binding?: Binding;
	  }
	| {
			readonly kind: "invalid";
			/** "shape" also covers a binding that no contributed sender binding recognises. */
			readonly reason: "signature" | "issuer" | "expired" | "shape" | "revoked";
	  };

export type Revocation =
	| { readonly kind: "revoked" }
	/** The token does not verify (or has expired), so there is nothing to revoke. */
	| { readonly kind: "invalid" }
	| { readonly kind: "unsupported" };

export type IssuedTo =
	| { readonly kind: "issued"; readonly issuedTo: string }
	| { readonly kind: "invalid" };

/** What a policy is asked: the grant as its caller verified it, its type, and its session (passed on unread). */
export interface IssuanceRequest {
	readonly grant: AccessGrant;
	readonly grantType: string;
	readonly session?: string;
	/** Set by the issuing side alone: this issuance continues a grant the policies already let through. */
	readonly continuing?: true;
}

/** A policy's verdict: `reason` is the audit's word, `description` the client's. */
export type IssuanceVerdict =
	| { readonly kind: "allowed" }
	| { readonly kind: "refused"; readonly reason: string; readonly description: string };

/** A rule an operator composes on whether an access token may be issued at all. */
export interface IssuancePolicy {
	readonly name: string;
	/** Throws Unavailable when it cannot tell. `signal` aborts at the policies' deadline, so it may stop its own work. */
	judge(request: IssuanceRequest, signal?: AbortSignal): Promise<IssuanceVerdict>;
}

export const issuancePolicies = extensionPoint<IssuancePolicy>("tokens.issuance-policies", {
	multiplicity: "keyed",
	keyOf: (policy) => policy.name,
});

export interface IssuanceRefused {
	readonly kind: "refused";
	readonly policy: string;
	readonly reason: string;
	readonly description: string;
}

export type Issued = { readonly kind: "issued"; readonly access: IssuedAccess } | IssuanceRefused;
export type Admitted = { readonly kind: "allowed" } | IssuanceRefused;

/** `notAfter` (epoch ms) caps the expiry; `lifetimeSeconds` (1–86400) replaces the section's lifetime. */
export interface IssueLimits {
	readonly notAfter?: number;
	readonly binding?: Binding;
	readonly lifetimeSeconds?: number;
}

/** Its `verifyAccess` is the validity `sender-binding` checks a token by at a resource. */
export interface Tokens extends TokenValidity<AccessCheck> {
	revocable(): boolean;
	/** Whether an access token may be issued for the request; the same judgment `issue` makes. */
	admits(request: IssuanceRequest): Promise<Admitted>;
	/** Issues once every policy, its own first, allows it; throws Unavailable when one cannot tell. */
	issue(request: IssuanceRequest, limits?: IssueLimits): Promise<Issued>;
	verifyAccess(token: string): Promise<AccessCheck>;
	revokeReferenced(reference: string): Promise<Revocation>;
	issuedToOf(token: string): Promise<IssuedTo>;
	revokeAccess(token: string): Promise<Revocation>;
}

export const tokens = contract<Tokens>("tokens");

export { referenceOf } from "./reference.ts";

export interface IssuedFor {
	readonly id: string;
	readonly subject: string;
	/** Epoch ms. */
	readonly issuedAt: number;
}

/** A condition every access token must still meet, contributed by the module that owns it. */
export interface AccessCondition {
	readonly name: string;
	/** Throws Unavailable when it cannot tell. */
	holds(token: IssuedFor): Promise<"holds" | "revoked">;
}

export const accessConditions = extensionPoint<AccessCondition>("tokens.access-conditions", {
	multiplicity: "keyed",
	keyOf: (condition) => condition.name,
});

/** Whether a token's subject was revoked after the token was issued. */
export interface SubjectCheck {
	/** Throws Unavailable when it cannot tell. */
	holds(token: IssuedFor): Promise<"holds" | "revoked">;
}

/**
 * The check of subject revocation on access tokens: exactly one, or none where the operator
 * states in the section that subjects are not checked.
 */
export const subjectChecks = extensionPoint<SubjectCheck>("tokens.subject-checks", {
	multiplicity: "many",
});

export * from "./store.ts";
