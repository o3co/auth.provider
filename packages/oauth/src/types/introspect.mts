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
 * interface (was inline JSON) so consumers can `import type` it and
 * so the `cnf` claim has a documented home. See Wave 2 Token-binding
 * Cluster spec §4.6.
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
	 * does not redefine the wire-level token type.
	 */
	readonly token_type?: "Bearer" | "DPoP";
	readonly jti?: string;
	/**
	 * RFC 7662 §2.2 confirmation claim mirror. Present when the introspected
	 * token carries a `cnf` claim; absent otherwise.
	 */
	readonly cnf?: Confirmation;
}
