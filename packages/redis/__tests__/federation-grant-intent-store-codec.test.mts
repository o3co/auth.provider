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

// How acquisition's records are written down (#593, D16, slice 6). Found by the
// mutation pass: the contract suite writes every record from one fixture
// object, so nothing in it could notice an encoding that depended on the order
// a caller built that object in, or a binding compared without its lengths.

import type { FederationGrantIntent } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	decodeFederationGrantIntent,
	encodeFederationGrantIntent,
	federationGrantBindingText,
	federationGrantIntentPairText,
} from "../src/internal/federation-grant-intent-codec.mjs";

const intent = (authorizationParams: Record<string, string>): FederationGrantIntent => ({
	handle: "h-1",
	kind: "initial",
	grantId: "g-1",
	clientId: "agent",
	subject: "u-1",
	connection: "okta-calendar",
	federation: "okta",
	identityRevision: "identity-1",
	authorizationRevision: "authorization-1",
	callbackUri: "https://provider.test/cb/okta-calendar",
	scopes: ["openid", "offline_access"],
	authorizationParams,
	redirectUri: "https://client.test/connected",
	clientState: "state-1",
	lifetimeMs: 86_400_000,
	createdAt: new Date(1_000),
	expiresAt: new Date(601_000),
	correlationId: "corr-1",
});

describe("the intent codec", () => {
	it("writes the same record to the same text whatever order its parameters were built in", () => {
		// The admission script answers `unchanged` for a retried write by
		// comparing text. Two instances building the same intent from the same
		// configuration must therefore agree byte for byte, or a retry reads as
		// a collision and a flow that was admitted is reported as refused.
		expect(encodeFederationGrantIntent(intent({ prompt: "consent", access_type: "offline" }))).toBe(
			encodeFederationGrantIntent(intent({ access_type: "offline", prompt: "consent" })),
		);
	});

	it("takes an empty parameter value, as the connection resolver does (Codex on slice 6)", () => {
		// `login_hint: ""` is a configuration the resolver accepts and the memory
		// store keeps; refusing it here made every lodging on that connection a
		// storage failure under Redis alone.
		const written = intent({ login_hint: "" });
		expect(decodeFederationGrantIntent(encodeFederationGrantIntent(written))).toEqual(written);
	});

	it("keeps every parameter it is handed as its own key, as the memory store does (Copilot)", () => {
		// Assigning a decoded `__proto__` into `{}` invokes the prototype setter
		// and drops it; the memory store's spread keeps it. The resolver refuses
		// the name at boot, and the codec does not rely on that.
		const written = intent(JSON.parse('{"__proto__": "x", "prompt": "consent"}'));
		const read = decodeFederationGrantIntent(encodeFederationGrantIntent(written));
		expect(Object.keys(read.authorizationParams).sort()).toEqual(["__proto__", "prompt"]);
		expect(Object.getOwnPropertyDescriptor(read.authorizationParams, "__proto__")?.value).toBe("x");
	});

	it("reads back what it wrote", () => {
		const written = intent({ access_type: "offline" });
		expect(decodeFederationGrantIntent(encodeFederationGrantIntent(written))).toEqual(written);
	});

	it("keeps two bindings apart when a separator could make them one", () => {
		// The answering script compares the binding as one string. Without the
		// lengths, a session ID ending where another browser's sid begins would
		// answer for it.
		expect(federationGrantBindingText({ sessionId: "a:b", sid: "c", subject: "u" })).not.toBe(
			federationGrantBindingText({ sessionId: "a", sid: "b:c", subject: "u" }),
		);
		expect(federationGrantIntentPairText("agent:x", "u-1")).not.toBe(
			federationGrantIntentPairText("agent", "x:u-1"),
		);
	});

	it("refuses a record it cannot read, rather than reading it as absent", () => {
		expect(() => decodeFederationGrantIntent("not json")).toThrow(
			/refused rather than read as absent/,
		);
		expect(() => decodeFederationGrantIntent("{}")).toThrow(/refused rather than read as absent/);
		expect(() =>
			decodeFederationGrantIntent(
				encodeFederationGrantIntent(intent({})).replace('"kind":"initial"', '"kind":"other"'),
			),
		).toThrow(/kind/);
	});
});
