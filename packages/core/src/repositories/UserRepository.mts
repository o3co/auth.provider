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
 * A federated identity to link to an existing user.
 *
 * `provider:sub` is the whole identity: the federation's name and the IdP's
 * opaque, stable subject. `claims` is what the IdP asserted, as the provider
 * mapped it (`email`, `emailVerified`, `name`, `picture`, ...), and it is
 * self-asserted upstream data. The rules a Store must apply before it links
 * (never on an unverified or relay address, never by e-mail alone) are in
 * the session package README.
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
 * The upstream registration an identity was issued under: the federation's
 * name, the issuer the id_token was verified against, and the client it was
 * issued to. All three come from the deployment's configuration of the
 * grant's connection, never from the upstream; `issuer` has already been
 * compared with the verified id_token's.
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
	 * id_token and nowhere else; `{}` when the connection names none. A callback
	 * missing any of them does not ask. Transient: the Store must not log,
	 * persist or echo them.
	 */
	readonly claims: Readonly<Record<string, string>>;
}

/** What {@link UserRepository.findSubjectByFederatedIdentity} answers. */
export type FederatedIdentityLookupResult =
	| { readonly kind: "linked"; readonly subject: string }
	| { readonly kind: "unlinked" }
	| {
			readonly kind: "indeterminate";
			readonly reason: "registration_not_covered" | "identity_not_resolvable";
	  };

/** What the Store answered a link request with. */
export type LinkFederatedIdentityResult =
	| { readonly ok: true; readonly user: User }
	| {
			readonly ok: false;
			/** `conflict`: the identity is already someone else's. `refused`: policy said no. */
			readonly reason: "refused" | "conflict";
			readonly description?: string;
	  };

export interface UserRepository {
	/** The user `username` and `password` authenticate, as plain data (see {@link User}), or `null`. */
	authenticate(username: string, password: string): Promise<User | null>;
	/**
	 * The user a federated identity token is linked to, as plain data (see
	 * {@link User}), or `null`. The Store answers the MFA enrollment witness
	 * (`User.mfaEnrolled`) here as on {@link authenticate}: a federated
	 * session records it from this answer.
	 */
	authenticateByToken(token: string): Promise<User | null>;
	/**
	 * Link a federated identity to an existing user. Optional: without it the
	 * federation start route refuses `link=1` with `link_unsupported` before
	 * sending the browser anywhere. Called by the federation callback only when
	 * the browser holds an authenticated session for `userId` and the identity
	 * resolves to no user; the Store answers `refused` (policy) or `conflict`
	 * (already another account's). Nothing links implicitly: without `link=1` an
	 * unknown identity stays `unknown_user`.
	 */
	linkFederatedIdentity?(
		userId: string,
		identity: FederatedIdentityLink,
	): Promise<LinkFederatedIdentityResult>;
	/**
	 * Whether this Store can answer {@link findSubjectByFederatedIdentity}
	 * completely for identities issued under `registration`. Synchronous and
	 * side-effect-free. Asked at boot for every federation-grant connection
	 * while `federation-grants.identityLookup` is `"required"`; only a literal
	 * `true` lets the deployment start. Implemented together with the lookup;
	 * one without the other is refused at boot.
	 *
	 * `true` means the Store can find every local link naming the person behind
	 * an identity, whichever registration the link was made through, and so can
	 * tell "linked to nobody" from "linked somewhere I cannot see". Keying links
	 * by federation name and `sub` cannot, where the IdP's `sub` is pairwise per
	 * registration (Entra's is). `identityClaims` is what the lookup will get as
	 * `claims`; a strategy that needs claims (Entra's `tid` and `oid`) answers
	 * `false` unless they are named. See ADR
	 * 2026-09-17-federation-grants-offline-delegation.
	 */
	supportsFederatedIdentityLookup?(
		registration: FederatedIdentityRegistration,
		identityClaims: readonly string[],
	): boolean;
	/**
	 * Who an upstream identity belongs to locally. Optional; a deployment says
	 * whether it has it with `federation-grants.identityLookup`, and one that
	 * requires it is refused at boot without it (and without
	 * {@link supportsFederatedIdentityLookup} answering `true` for every
	 * connection's registration).
	 *
	 * The grant callback asks this to refuse a delegation whose upstream account
	 * already belongs to another local user. It MUST change nothing: no login
	 * recorded, no link made, no user created, no claims merged, nothing inferred
	 * from an email. `authenticateByToken` cannot stand in: it has login
	 * semantics.
	 *
	 * Answers are about ownership across every registration:
	 *
	 * - `linked`: a complete resolution found exactly one local owner; `subject`
	 *   is its `User.id`. Several links naming the same user are one owner.
	 * - `unlinked`: a complete resolution established that no local user holds
	 *   this person, not merely that a search of one namespace found no rows.
	 * - `indeterminate`: neither. `registration_not_covered`: no strategy for
	 *   this registration (coverage lost since boot). `identity_not_resolvable`:
	 *   a strategy, but this identity is not in it. The callback refuses.
	 *
	 * Throws when the backend cannot answer or its data names more than one
	 * owner: the answer decides a refusal, and an arbitrary pick is worse than
	 * an outage.
	 */
	findSubjectByFederatedIdentity?(
		identity: FederatedIdentityLookup,
	): Promise<FederatedIdentityLookupResult>;
	/**
	 * Persist whether `subject` has a second factor enrolled: the MFA enrollment
	 * witness the Store answers on `authenticate` and on `authenticateByToken`
	 * as `User.mfaEnrolled`. Optional; detected by
	 * {@link supportsMfaEnrollmentWitness}.
	 *
	 * The provider decides and the Store only persists: `true` after the first
	 * counting factor has been written, `false` after the last one is removed or
	 * reset, so a crash in between never leaves a witness without a factor.
	 * Idempotent. A backend that cannot answer throws. See the MFA ADR
	 * (2026-09-25-multi-factor-authentication), D12.
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
// ComponentMap slot declaration
//
// `userRepository` is produced by a composition-root-local module (e.g. the
// standalone template's `repositoriesModule`). Modules that authenticate
// users declare `requires: ["userRepository"]`.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly userRepository: UserRepository;
	}
}

/**
 * What the MFA enrollment witness says (the MFA ADR's D12): `enrolled`,
 * `not_enrolled`, or `malformed` — a value the Store should not have answered.
 */
export type MfaEnrollmentWitness = "enrolled" | "not_enrolled" | "malformed";

/**
 * The one reading of `User.mfaEnrolled`, for the `User` a primary sign-in's
 * `authenticate` or `authenticateByToken` answered and for the session's
 * snapshot of it alike: `true` is `enrolled`; `false` or absent is
 * `not_enrolled`; any other value (`1`, `"true"`, `null`) is `malformed`. A
 * malformed witness is never read as "not enrolled", which would open a first
 * binding to whoever holds the password: the MFA package answers it
 * `503 temporarily_unavailable` and binds nothing (the MFA ADR's D12).
 */
export function readMfaEnrollmentWitness(
	user: Readonly<Record<string, unknown>>,
): MfaEnrollmentWitness {
	const value = user.mfaEnrolled;
	if (value === true) return "enrolled";
	if (value === false || value === undefined) return "not_enrolled";
	return "malformed";
}
