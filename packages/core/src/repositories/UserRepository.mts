/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type { User } from "./types.mjs";

/**
 * A federated identity to link to an existing user (#482).
 *
 * `provider:sub` is the whole identity: the federation's name and the IdP's
 * opaque, stable subject. `claims` is what the IdP asserted, as the provider
 * mapped it — `email`, `emailVerified`, `name`, `picture`, and whatever else
 * the adapter surfaces — and it is self-asserted upstream data. The rules a
 * Store must apply before it links (never on an unverified or relay address,
 * never by e-mail alone) are in the session package README.
 */
export interface FederatedIdentityLink {
	/** The federation name — the `:name` route segment, e.g. `"apple"`. */
	readonly provider: string;
	/** The IdP's stable subject identifier for this person. Opaque; never derived from `email`. */
	readonly sub: string;
	/** `<provider>:<sub>` — exactly what `authenticateByToken` will be asked for next time. */
	readonly token: string;
	/** The provider's mapped claims for this login. */
	readonly claims: Readonly<Record<string, unknown>>;
}

/**
 * The upstream registration an identity was issued under (#611): the
 * federation's name, the issuer the id_token was verified against, and the
 * client it was issued to. All three come from the deployment's configuration
 * of the grant's connection, never from the upstream; `issuer` has already
 * been compared with the verified id_token's.
 */
export interface FederatedIdentityRegistration {
	readonly provider: string;
	readonly issuer: string;
	readonly clientId: string;
}

/** An identity as the connect callback asks about it: a registration, and the verified `sub`. */
export interface FederatedIdentityLookup extends FederatedIdentityRegistration {
	/** The verified id_token's `sub`. Pairwise per registration at some IdPs. */
	readonly sub: string;
	/**
	 * The connection's `identityClaims`, each one present, from the verified
	 * id_token and nowhere else (#611) — `{}` when the connection names none. A
	 * callback missing any of them does not ask. Transient: the Store must not
	 * log, persist or echo them.
	 */
	readonly claims: Readonly<Record<string, string>>;
}

/** What {@link UserRepository.findSubjectByFederatedIdentity} answers (#611). */
export type FederatedIdentityLookupResult =
	| { readonly kind: "linked"; readonly subject: string }
	| { readonly kind: "unlinked" }
	| {
			readonly kind: "indeterminate";
			readonly reason: "registration_not_covered" | "identity_not_resolvable";
	  };

/** What the Store answered a link request with (#482). */
export type LinkFederatedIdentityResult =
	| { readonly ok: true; readonly user: User }
	| {
			readonly ok: false;
			/** `conflict`: the identity is already someone else's. `refused`: policy said no. */
			readonly reason: "refused" | "conflict";
			readonly description?: string;
	  };

export interface UserRepository {
	authenticate(username: string, password: string): Promise<User | null>;
	authenticateByToken(token: string): Promise<User | null>;
	/**
	 * Link a federated identity to an existing user (#482). Optional: a Store
	 * that does not implement it makes linking unavailable — the federation
	 * start route refuses `link=1` with `link_unsupported` before sending the
	 * browser anywhere. Called by the federation callback only when the
	 * browser holds an authenticated session for `userId` and the identity
	 * resolves to no user; the Store decides, and answers `refused` (policy)
	 * or `conflict` (the identity is already another account's). Nothing
	 * links implicitly: without `link=1` an unknown identity stays
	 * `unknown_user`.
	 */
	linkFederatedIdentity?(
		userId: string,
		identity: FederatedIdentityLink,
	): Promise<LinkFederatedIdentityResult>;
	/**
	 * Whether this Store can answer {@link findSubjectByFederatedIdentity}
	 * completely for identities issued under `registration` (#611). Synchronous
	 * and side-effect-free; asked at boot for every federation-grant connection
	 * while `federationGrants.identityLookup` is `"required"`, and only a literal
	 * `true` lets the deployment start.
	 *
	 * `true` is a statement about an implemented strategy, not about any one
	 * person: that for this registration the Store can find every local link
	 * that names the person behind an identity — whichever registration of the
	 * IdP that link was made through — and so can tell "linked to nobody" from
	 * "linked somewhere I cannot see". A Store that only keys links by
	 * federation name and `sub` cannot say that for a registration of its own,
	 * because a login links under the federation the user signed in through,
	 * and an IdP whose `sub` is pairwise per registration (Entra's is) gives the
	 * same person another `sub` under every registration. Required together
	 * with the lookup; one without the other is refused at boot.
	 *
	 * `identityClaims` is what the connection will hand the lookup as `claims`
	 * (#611). A Store whose strategy needs claims answers `false` unless they
	 * are named — a directory keyed by Entra's tenant and object id needs both
	 * `tid` and `oid`. A Store that learns identities only from logins, where
	 * `<provider>:<sub>` is all it is told, cannot cover a registration whose
	 * `sub` is pairwise at all: that `sub` is first seen at the grant callback.
	 */
	supportsFederatedIdentityLookup?(
		registration: FederatedIdentityRegistration,
		identityClaims: readonly string[],
	): boolean;
	/**
	 * Who an upstream identity belongs to locally (#593, D7 check 5; #611).
	 * Optional; a deployment says whether it has it with
	 * `federationGrants.identityLookup`, and one that requires it is refused at
	 * boot without it (and without {@link supportsFederatedIdentityLookup}
	 * answering `true` for every connection's registration).
	 *
	 * The grant callback asks this to refuse a delegation whose upstream account
	 * already belongs to another local user. `authenticateByToken` cannot stand
	 * in: it carries login semantics, and a Store may stamp a last login or
	 * provision a user on first sight. So this one MUST change nothing — no
	 * login recorded, no link made, no user created, no claims merged, nothing
	 * inferred from an email.
	 *
	 * The answers are about ownership across every registration, not about the
	 * one the identity came through:
	 *
	 * - `linked` — a complete resolution found exactly one local owner; its
	 *   `subject` is that user's `id` (what `User.id` is everywhere else).
	 *   Several links that all name the same user are one owner.
	 * - `unlinked` — a complete resolution established that no local user holds
	 *   this person. Not "this query returned no rows": a Store that searched
	 *   only the namespace it was given, where a link could live elsewhere, has
	 *   not established this.
	 * - `indeterminate` — it cannot say either. `registration_not_covered`: it
	 *   has no strategy for this registration (boot asked, so this means
	 *   coverage was lost since). `identity_not_resolvable`: it has one, and
	 *   this identity is not in it — an alias it was never told of, records
	 *   whose provenance it does not know. The callback refuses the delegation.
	 *
	 * A backend that cannot answer throws, and so does one whose data names more
	 * than one owner: the answer decides whether a delegation is refused as
	 * somebody else's, and an arbitrary pick is worse than an outage.
	 */
	findSubjectByFederatedIdentity?(
		identity: FederatedIdentityLookup,
	): Promise<FederatedIdentityLookupResult>;
	/**
	 * Tell the Store whether `subject` has a second factor enrolled — the MFA
	 * enrollment witness it answers on `authenticate` as `User.mfaEnrolled`
	 * (the MFA ADR's D12). Optional; detected by
	 * {@link supportsMfaEnrollmentWitness}.
	 *
	 * The provider decides and the Store only persists. It is called with
	 * `true` after the first counting factor has been written, and with
	 * `false` after the last one was removed or an operator reset every factor
	 * — so a crash between the two leaves a factor without a witness, never a
	 * witness without a factor. A verification whose `User` lacks the witness
	 * while a counting factor exists marks it again. Idempotent. A backend that
	 * cannot answer throws.
	 */
	markMfaEnrolled?(subject: string, enrolled: boolean): Promise<void>;
}

/** A `UserRepository` that can write the MFA enrollment witness. */
export interface SupportsMfaEnrollmentWitness {
	markMfaEnrolled(subject: string, enrolled: boolean): Promise<void>;
}

/**
 * Whether `repository` can write the MFA enrollment witness (the MFA ADR's
 * D12), detected by method presence like the other optional capabilities. A
 * repository without it leaves the witness to whatever the Store answers on
 * `authenticate`, which may be nothing.
 */
export function supportsMfaEnrollmentWitness(
	repository: UserRepository,
): repository is UserRepository & SupportsMfaEnrollmentWitness {
	return (
		typeof (repository as Partial<SupportsMfaEnrollmentWitness>).markMfaEnrolled === "function"
	);
}

// ---------------------------------------------------------------------------
// ComponentMap slot declaration (per A2-α §6.1)
//
// `userRepository` is a core component produced by a composition-root-local
// module (e.g. `repositoriesModule` in A2-γ §3.8 standalone template). Modules
// that authenticate users (sessionModule's /login, federation routes after
// callback) declare `requires: ["userRepository"]` and receive the instance
// through the typed DI graph.
//
// Per A2-γ §3.4: sessionModule requires userRepository in its manifest.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly userRepository: UserRepository;
	}
}
