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
	type SubjectRevocation,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";

export interface FederationTokenRouterOptions {
	keyStore: KeyStore;
	refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
	userSessionStore: UserSessionStore;
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
	 * Tokens within this many milliseconds of expiry are proactively refreshed.
	 * Default: 30_000 (30 seconds). A positive finite number, or building the
	 * route throws a `RangeError`.
	 */
	refreshBufferMs?: number;
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
		step: "get" | "list" | "acquire_lock" | "get_after_lock" | "update",
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
	/** Tokens expiring within this many milliseconds are refreshed. */
	readonly refreshBufferMs: number;
}

/** The access token's claims the later stages act on, each present. */
export interface FederationTokenCaller {
	readonly familyId: string;
	readonly sid: string;
	readonly azp: string;
	/** Audited when the token names one; never required. */
	readonly sub: string | null;
}
