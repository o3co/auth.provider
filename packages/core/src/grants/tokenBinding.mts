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
import type { Confirmation } from "./confirmation.mjs";

/**
 * Sender-constrained binding established by a transport-layer mechanism.
 * Core owns the cross-cutting shape (discriminator + `cnf` claim); mechanism
 * packages add their own evidence fields. See ADR
 * 2026-05-20-token-binding-first-class-abstraction.
 *
 * Downstream may add a `kind` and evidence fields, but `confirmation` must be
 * a `Confirmation` variant (RFC 7800 / IANA registry); a new variant is a
 * core semver-minor change.
 *
 * A binding binds only through the member its `kind` owns in core's
 * `BINDING_PROFILES` (`grants/confirmationMatch.mts`). One without (a kind
 * core has no profile for, or another kind's member) binds nothing: the token
 * is issued unbound as Bearer, and a client whose `senderConstrained.required`
 * allows its kind is refused `invalid_request` rather than downgraded. A new
 * kind that should bind tokens lands its profile in core first.
 */
export interface TokenBinding {
	readonly kind: string;
	readonly confirmation: Confirmation;
	/**
	 * Headers the HTTP answer to this request should carry, set by the
	 * token-binding middlewares: a DPoP mechanism with server-provided nonces
	 * returns the current `DPoP-Nonce` on every accepted proof (RFC 9449 §8),
	 * so a client learns of a rotation before it needs to.
	 */
	readonly responseHeaders?: Readonly<Record<string, string>>;
}
