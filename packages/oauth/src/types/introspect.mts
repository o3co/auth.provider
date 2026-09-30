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
 */
import type { Confirmation } from "@o3co/auth-provider-core";

/**
 * RFC 7662 §2.2 token introspection response, typed so consumers (e.g. the
 * auth.proxy validation layer) can import it and the `cnf` claim has a
 * documented home.
 *
 * The optional members `username` and `nbf` are omitted: this AS issues
 * `at+jwt` tokens without `nbf` and does not persist a human-readable
 * `username` (profile storage is out of scope). Add them when a consumer
 * needs them.
 */
export interface IntrospectResponse {
	readonly active: boolean;
	readonly exp?: number;
	readonly iat?: number;
	readonly iss?: string;
	readonly aud?: string | readonly string[];
	readonly sub?: string;
	readonly azp?: string;
	readonly client_id?: string;
	readonly scope?: string;
	/**
	 * Wire-level token type: `"DPoP"` when the introspected token carries a
	 * `cnf.jkt` claim (RFC 9449 §5, RFC 7662 §2.2), `"Bearer"` otherwise —
	 * including mTLS-bound tokens, since RFC 8705 does not redefine the
	 * wire-level token type. A new variant (a sender-constrained scheme with
	 * its own IANA token-type registration) is a core semver-minor change,
	 * like the `Confirmation` extension boundary.
	 */
	readonly token_type?: "Bearer" | "DPoP";
	readonly jti?: string;
	/**
	 * RFC 7662 §2.2 confirmation claim mirror. Present when the introspected
	 * token carries a `cnf` claim; absent otherwise.
	 */
	readonly cnf?: Confirmation;
	/**
	 * RFC 9470 §6.2: the Authentication Context Class Reference the token
	 * carries, when it carries a non-empty string.
	 */
	readonly acr?: string;
	/**
	 * RFC 8176 authentication methods the token carries, when it carries a
	 * non-empty array of non-empty strings: what the session vouched for.
	 */
	readonly amr?: readonly string[];
	/**
	 * RFC 9470 §6.2: when the user authenticated, in seconds since the epoch —
	 * the primary authentication's time, which a step-up does not move. Absent
	 * when the token carries none.
	 */
	readonly auth_time?: number;
}

/**
 * `extractConfirmation` and `isCompoundConfirmation` live in core with the
 * `Confirmation` union (`core/grants/confirmationMatch.mts`): the raw-cnf
 * shape rules they encode are the rows `matchConfirmation` evaluates.
 * Re-exported here because this package's barrel publishes them.
 */
export { extractConfirmation, isCompoundConfirmation } from "@o3co/auth-provider-core";
