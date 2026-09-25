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
import type { TokenBinding } from "@o3co/auth-provider-core";

/**
 * Bindings a grant may be handed whose confirmation no mechanism that owns it
 * validated: a contributed mechanism kind presenting a DPoP or an mTLS member,
 * and a DPoP binding presenting an mTLS member. `Confirmation` is extensible
 * by mechanism, and `ctx.tokenBinding` carries what the mechanism returned, so
 * each grant must stamp only the member the binding's kind owns — core's
 * `ownedConfirmation` — and nothing here is one. An access or refresh token
 * minted from one of these carries no `cnf` and is advertised as Bearer.
 */
export const UNOWNED_BINDINGS: readonly (readonly [string, TokenBinding])[] = [
	["a contributed kind presenting cnf.jkt", { kind: "acme", confirmation: { jkt: "ACME-JKT" } }],
	[
		"a contributed kind presenting cnf.x5t#S256",
		{ kind: "acme", confirmation: { "x5t#S256": "ACME-X5T" } },
	],
	[
		"a DPoP binding presenting cnf.x5t#S256",
		{ kind: "dpop", confirmation: { "x5t#S256": "CROSSED-X5T" } },
	],
];

/**
 * A DPoP binding whose confirmation also carries an mTLS member. The grant
 * stamps the member DPoP owns and nothing else: this provider mints one
 * mechanism's confirmation per token, and a compound `cnf` is what every
 * surface that reads one refuses.
 */
export const COMPOUND_DPOP_BINDING = {
	kind: "dpop",
	confirmation: { jkt: "OWNED-JKT", "x5t#S256": "STOWAWAY-X5T" },
} as unknown as TokenBinding;
