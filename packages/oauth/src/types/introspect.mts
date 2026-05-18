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
 * RFC 7662 §2.2 token introspection response. Pulled into a typed
 * interface (was inline JSON) so consumers (e.g. auth.proxy validation
 * layer) can `import type { IntrospectResponse } from "@o3co/auth-
 * provider-oauth"` and so the `cnf` claim has a documented home. See
 * Wave 2 Token-binding Cluster spec §4.6.
 *
 * RFC 7662 §2.2 optional members `username` and `nbf` are intentionally
 * omitted: this AS issues `at+jwt` tokens without `nbf` and does not
 * persist a human-readable `username` (auth.provider's scope excludes
 * profile storage — see project scope memory). Add them when a
 * consumer needs them.
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
	 * Wire-level token type. `"DPoP"` when the introspected token carries
	 * a `cnf.jkt` claim (per RFC 9449 §5 + RFC 7662 §2.2 consistency).
	 * `"Bearer"` otherwise — including mTLS-bound tokens, because RFC 8705
	 * does not redefine the wire-level token type. Adding a new
	 * `token_type` variant (e.g. for a future sender-constrained scheme
	 * with its own IANA token-type registration) is a core semver-minor
	 * change, mirroring the `Confirmation` extension boundary in spec
	 * §4.3.
	 */
	readonly token_type?: "Bearer" | "DPoP";
	readonly jti?: string;
	/**
	 * RFC 7662 §2.2 confirmation claim mirror. Present when the introspected
	 * token carries a `cnf` claim; absent otherwise.
	 */
	readonly cnf?: Confirmation;
}

/**
 * Validate and narrow a raw `cnf` claim value extracted from a JWT
 * payload into a `Confirmation`. Returns `undefined` when the value
 * is missing or fails any of:
 *
 * - non-object (null, array, primitive)
 * - missing both `jkt` and `x5t#S256` members
 * - member value is not a non-empty string
 *
 * Empty-string members are rejected because RFC 9449 §6 / RFC 8705 §3
 * define both `jkt` (RFC 7638 JWK Thumbprint) and `x5t#S256` (DER cert
 * SHA-256 thumbprint) as non-empty base64url strings.
 *
 * Compound binding (a cnf object carrying BOTH `jkt` and `x5t#S256`)
 * is out of scope for Stage 1 (spec §1 "out of scope"). If both are
 * present, this helper returns the `jkt` variant — matching the intent-
 * explicit dispatch policy (spec §3.5) where DPoP wins over an ambient
 * mTLS signal.
 */
export const extractConfirmation = (raw: unknown): Confirmation | undefined => {
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
	const obj = raw as Record<string, unknown>;
	const jkt = obj.jkt;
	if (typeof jkt === "string" && jkt.length > 0) {
		return { jkt };
	}
	const x5t = obj["x5t#S256"];
	if (typeof x5t === "string" && x5t.length > 0) {
		return { "x5t#S256": x5t };
	}
	return undefined;
};
