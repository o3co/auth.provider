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

/**
 * What every stage of the federation token route reads: the router's options,
 * the per-request context (the federation's name as sent and as logged, the
 * logger, the store-outage line) and the claims of the caller's access token.
 */

import {
	type AccessTokenDenylist,
	type AuditSink,
	type ClientRepository,
	type FederationProvider,
	type FederationTokenStore,
	type KeyStore,
	type Logger,
	loggableError,
	type RefreshTokenFamilyRevocation,
	type SessionFederationIndex,
	type SessionLifecycle,
	type SubjectRevocation,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";

export interface FederationTokenRouterOptions {
	keyStore: KeyStore;
	refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
	userSessionStore: UserSessionStore;
	/**
	 * Core's session lifecycle. Where installed, it answers whether the
	 * caller's session is live in place of `userSessionStore`: a session whose
	 * close has committed is not live.
	 */
	sessionLifecycle?: SessionLifecycle;
	sessionFederationIndex: SessionFederationIndex;
	federationTokenStore: FederationTokenStore;
	clientRepository: ClientRepository;
	/** RFC 7009: when wired, verifyJwt consults the denylist so revoked access tokens answer 401. */
	accessTokenDenylist?: AccessTokenDenylist;
	/**
	 * When wired, verifyJwt rejects an access token whose `iat` is at or before
	 * this subject's revocation watermark: the denylist revokes a named token,
	 * this revokes every token a subject held as of a credential change.
	 */
	subjectRevocation?: SubjectRevocation;
	/**
	 * Getter for the federation providers Map. Evaluated at request time (not at
	 * router construction time) so module init order does not matter.
	 * Returns undefined when federation is not configured.
	 */
	getFederationProviders: () => ReadonlyMap<string, FederationProvider> | undefined;
	/** Audit sink for operator observability events. No-op when undefined. */
	auditSink?: AuditSink;
	/** Structured logger. Defaults to console when undefined. */
	logger?: Logger;
	/**
	 * How far ahead of its expiry a stored token becomes due for refresh. A
	 * token whose record says when it was obtained is refreshed within it only
	 * once half spent, except that one with less than a second left is
	 * refreshed whether half spent or not. It is the
	 * refresh margin only: the clock skew tolerated between replicas is the
	 * runbook's one second, not this value. Default: 30_000 (30 seconds). A
	 * whole number from 1000 to 2^31 - 1, or building the route throws a
	 * `RangeError`.
	 */
	refreshBufferMs?: number;
	/**
	 * The longest a refreshed upstream token is stored for, in milliseconds,
	 * counted from when the refresh answer is read: a longer lifetime is
	 * capped, never refused. Default: 86_400_000 (24 hours). A whole number
	 * greater than `refreshBufferMs` and at most 365 days, or building the
	 * route throws a `RangeError`.
	 */
	maxTokenLifetimeMs?: number;
	/** Configured issuer, pinned by the central verifier. */
	issuer?: string;
	/**
	 * Accept tokens with no `typ` header, logging `jwt_verify_legacy_typ`.
	 * Default `false`; `true` is a legacy opt-in.
	 */
	legacyTypAccept?: boolean;
}

/**
 * A store that cannot answer is `503`, logged once as
 * `federation_token_store_unavailable` with `store` and `step` and the
 * error's projection — never the error, which may quote a token record.
 */
export const createStoreUnavailableLog =
	(logger: Logger | Console) =>
	(
		federation: string,
		store: "user_session" | "session_federation_index" | "federation_token",
		step:
			| "get"
			| "list"
			| "acquire_lock"
			| "get_after_lock"
			| "get_after_conflict"
			| "get_before_serve"
			| "replace_if",
		error: unknown,
	): void => {
		logger.error(
			{ federation, store, step, err: loggableError(error) },
			"federation_token_store_unavailable",
		);
	};

/** What each stage of one request reads. */
export interface FederationTokenContext {
	readonly opts: FederationTokenRouterOptions;
	readonly req: Request;
	readonly res: Response;
	/** The federation as the path names it: the key into the stores and the provider map. */
	readonly name: string;
	/** `name` sanitised and capped: what every log line and audit event carries. */
	readonly federation: string;
	readonly logger: Logger | Console;
	readonly storeUnavailable: ReturnType<typeof createStoreUnavailableLog>;
	/** Tokens expiring within this many milliseconds are refreshed, once half spent when their age is known. */
	readonly refreshBufferMs: number;
	/** A refreshed token is stored for at most this many milliseconds. */
	readonly maxTokenLifetimeMs: number;
}

/** The access token's claims the later stages act on, each present. */
export interface FederationTokenCaller {
	readonly familyId: string;
	readonly sid: string;
	readonly azp: string;
	/** Audited when the token names one; never required. */
	readonly sub: string | null;
}
