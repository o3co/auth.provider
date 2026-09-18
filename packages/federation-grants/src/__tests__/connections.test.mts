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
 * `federationGrants.connections.<name>` read into the connections the domain
 * rules take (#593, D4/D6/D15).
 *
 * Everything here is a boot refusal, and the reason it is a boot refusal
 * rather than a per-request failure is the same each time: what these values
 * decide — which upstream account a grant is pinned to, how much residual
 * access it may carry, which environment it belongs to — is decided once, at
 * consent, and lives for as long as the grant does. An operator finds out at
 * boot, or finds out from a user.
 */

import { describe, expect, it } from "vitest";
import { resolveFederationGrantConnections } from "#/connections.mjs";

const FEDERATIONS = {
	upstream: {
		enabled: true,
		issuer: "https://issuer.example",
		clientId: "provider-client",
	},
	disabled: { enabled: false, issuer: "https://off.example", clientId: "x" },
	noIssuer: { enabled: true, clientId: "y" },
};

const CONNECTION = {
	federation: "upstream",
	scopes: ["openid", "offline_access", "Files.Read"],
	boundary: "production",
	maxAccessTokenLifetime: 3600,
};

const resolve = (connections: Record<string, unknown>, federations: unknown = FEDERATIONS) =>
	resolveFederationGrantConnections({ federations, federationGrants: { connections } });

describe("resolveFederationGrantConnections", () => {
	it("joins the entry with the issuer and client id the federation is configured with", () => {
		// Never with what a discovery document returned: the pair goes into a
		// persisted fingerprint, and what goes into that must change only when
		// an operator changes it.
		const connections = resolve({ graph: CONNECTION });
		const graph = connections.get("graph");
		expect(graph).toMatchObject({
			name: "graph",
			federation: "upstream",
			upstreamIssuer: "https://issuer.example",
			upstreamClientId: "provider-client",
			scopes: ["openid", "offline_access", "Files.Read"],
			boundary: "production",
			maxAccessTokenLifetime: 3600,
		});
	});

	it("is empty, and valid, when an operator has removed every connection", () => {
		// Removing the last one must stay an operable change: a deployment with
		// no connections issues no new grants and still answers about the ones
		// it has.
		expect(resolveFederationGrantConnections({ federations: FEDERATIONS }).size).toBe(0);
		expect(resolve({}).size).toBe(0);
	});

	it("defaults allowScopeSubsets to true and authorizationParams to nothing", () => {
		const graph = resolve({ graph: CONNECTION }).get("graph");
		expect(graph?.allowScopeSubsets).toBe(true);
		expect(graph?.authorizationParams).toEqual({});
	});

	it("reads allowScopeSubsets in the spellings an environment variable arrives in", () => {
		expect(
			resolve({ g: { ...CONNECTION, allowScopeSubsets: "false" } }).get("g")?.allowScopeSubsets,
		).toBe(false);
		expect(
			resolve({ g: { ...CONNECTION, allowScopeSubsets: "0" } }).get("g")?.allowScopeSubsets,
		).toBe(false);
	});

	it("refuses a connection pointing at a federation that is missing or switched off", () => {
		expect(() => resolve({ g: { ...CONNECTION, federation: "absent" } })).toThrow(/absent/);
		expect(() => resolve({ g: { ...CONNECTION, federation: "disabled" } })).toThrow(/disabled/);
	});

	it("refuses a federation with no configured issuer rather than guessing one", () => {
		// A bundled adapter that knows its own issuer is not a source for this:
		// the value is persisted into a grant's identity, so it has to be one
		// an operator can see and change.
		expect(() => resolve({ g: { ...CONNECTION, federation: "noIssuer" } })).toThrow(/issuer/);
	});

	it("refuses a name that is not a name", () => {
		expect(() => resolve({ "": CONNECTION })).toThrow();
		expect(() => resolve({ "has space": CONNECTION })).toThrow(/has space/);
		expect(() => resolve({ "graph:prod": CONNECTION })).toThrow(/graph:prod/);
	});

	it("requires the scopes, and requires openid among them", () => {
		expect(() => resolve({ g: { ...CONNECTION, scopes: [] } })).toThrow(/scopes/);
		expect(() => resolve({ g: { ...CONNECTION, scopes: ["offline_access"] } })).toThrow(/openid/);
		expect(() => resolve({ g: { ...CONNECTION, scopes: ["openid", "openid"] } })).toThrow(
			/duplicate/i,
		);
		expect(() => resolve({ g: { ...CONNECTION, scopes: ["openid", "a b"] } })).toThrow();
	});

	it("does not require offline_access, because providers differ in how they ask for one", () => {
		expect(() => resolve({ g: { ...CONNECTION, scopes: ["openid", "Files.Read"] } })).not.toThrow();
	});

	it("requires a boundary and keeps its spelling exactly", () => {
		expect(() => resolve({ g: { ...CONNECTION, boundary: "" } })).toThrow(/boundary/);
		expect(() => resolve({ g: { ...CONNECTION, boundary: undefined } })).toThrow(/boundary/);
		expect(resolve({ g: { ...CONNECTION, boundary: " Prod " } }).get("g")?.boundary).toBe(" Prod ");
	});

	it("requires a positive access-token maximum and guesses none", () => {
		// A guessed one invents a residual-access policy (D15): how long a
		// token this provider hands out keeps working after the grant is gone.
		expect(() => resolve({ g: { ...CONNECTION, maxAccessTokenLifetime: undefined } })).toThrow(
			/maxAccessTokenLifetime/,
		);
		expect(() => resolve({ g: { ...CONNECTION, maxAccessTokenLifetime: 0 } })).toThrow();
		expect(() => resolve({ g: { ...CONNECTION, maxAccessTokenLifetime: -1 } })).toThrow();
		expect(() => resolve({ g: { ...CONNECTION, maxAccessTokenLifetime: "soon" } })).toThrow();
	});

	it("refuses an access-token maximum that is not a whole number of seconds", () => {
		// Found by review. `Number(x)` took `true` as one second and `[5]` as
		// five, and a fraction is not a thing an upstream's `expires_in` can
		// be compared with.
		for (const maxAccessTokenLifetime of [0.5, true, [5], "1e3", null, new Date(5)]) {
			expect(
				() => resolve({ g: { ...CONNECTION, maxAccessTokenLifetime } }),
				JSON.stringify(maxAccessTokenLifetime),
			).toThrow(/maxAccessTokenLifetime/);
		}
		expect(
			resolve({ g: { ...CONNECTION, maxAccessTokenLifetime: "3600" } }).get("g")
				?.maxAccessTokenLifetime,
		).toBe(3600);
	});

	it("refuses a resource that is not somewhere this provider could ask for a token", () => {
		// Found by review: `new URL()` parses `javascript:alert(1)` happily,
		// and userinfo in a resource indicator is a credential in a value that
		// is echoed to an upstream. `callbackURL` already refused both.
		expect(() => resolve({ g: { ...CONNECTION, resource: "javascript:alert(1)" } })).toThrow(
			/resource/,
		);
		expect(() => resolve({ g: { ...CONNECTION, resource: "https://u:p@api.example/" } })).toThrow(
			/resource/,
		);
	});

	it("takes a resource as an absolute URI without a fragment, spelled as written", () => {
		expect(
			resolve({ g: { ...CONNECTION, resource: "https://graph.example/v1.0" } }).get("g")?.resource,
		).toBe("https://graph.example/v1.0");
		expect(() => resolve({ g: { ...CONNECTION, resource: "/v1.0" } })).toThrow(/resource/);
		expect(() => resolve({ g: { ...CONNECTION, resource: "https://graph.example/#f" } })).toThrow(
			/fragment/,
		);
	});

	it("refuses an authorization parameter the provider owns", () => {
		// Slice 2's exclusion, not a list of permitted vendor parameters: what
		// matters is that configuration cannot take over the PKCE challenge,
		// the state, the nonce or the redirect this provider computes.
		for (const key of ["code_challenge", "state", "nonce", "redirect_uri", "scope", "resource"]) {
			expect(
				() => resolve({ g: { ...CONNECTION, authorizationParams: { [key]: "x" } } }),
				key,
			).toThrow(new RegExp(key));
		}
		expect(() => resolve({ g: { ...CONNECTION, authorizationParams: { prompt: 1 } } })).toThrow(
			/prompt/,
		);
		expect(
			resolve({ g: { ...CONNECTION, authorizationParams: { prompt: "consent" } } }).get("g")
				?.authorizationParams,
		).toEqual({ prompt: "consent" });
	});

	it("takes a callback URL when one is supplied, and refuses an unusable one", () => {
		// Optional here: a worker spending a grant never performs the browser
		// flow. Slice 6 makes it mandatory, with the flow it belongs to.
		expect(() => resolve({ g: CONNECTION })).not.toThrow();
		expect(() =>
			resolve({ g: { ...CONNECTION, callbackURL: "https://app.example/cb" } }),
		).not.toThrow();
		expect(() =>
			resolve({ g: { ...CONNECTION, callbackURL: "http://localhost:3000/cb" } }),
		).not.toThrow();
		expect(() => resolve({ g: { ...CONNECTION, callbackURL: "http://app.example/cb" } })).toThrow(
			/callbackURL/,
		);
		expect(() =>
			resolve({ g: { ...CONNECTION, callbackURL: "https://u:p@app.example/cb" } }),
		).toThrow(/callbackURL/);
		expect(() =>
			resolve({ g: { ...CONNECTION, callbackURL: "https://app.example/cb#x" } }),
		).toThrow(/callbackURL/);
	});

	it("refuses a connection entry that is not a configuration block", () => {
		expect(() => resolve({ g: "not-a-block" })).toThrow(/g/);
		expect(() => resolve({ g: ["not", "a", "block"] })).toThrow(/g/);
		expect(() => resolve({ g: null })).toThrow(/g/);
	});

	it("refuses a connection that names no federation", () => {
		expect(() => resolve({ g: { ...CONNECTION, federation: undefined } })).toThrow(/federation/);
		expect(() => resolve({ g: { ...CONNECTION, federation: "" } })).toThrow(/federation/);
		expect(() => resolve({ g: { ...CONNECTION, federation: 7 } })).toThrow(/federation/);
	});

	it("refuses a federation with no configured client id", () => {
		expect(() =>
			resolve({ g: CONNECTION }, { upstream: { enabled: true, issuer: "https://i.example" } }),
		).toThrow(/clientId/);
	});

	it("names the four spellings when allowScopeSubsets is none of them", () => {
		expect(() => resolve({ g: { ...CONNECTION, allowScopeSubsets: "maybe" } })).toThrow(
			/"true", "false", "1" or "0"/,
		);
		expect(() => resolve({ g: { ...CONNECTION, allowScopeSubsets: 1 } })).toThrow(
			/allowScopeSubsets/,
		);
	});

	it("refuses authorizationParams that is not a map", () => {
		for (const authorizationParams of ["prompt=consent", ["prompt"], 7]) {
			expect(
				() => resolve({ g: { ...CONNECTION, authorizationParams } }),
				JSON.stringify(authorizationParams),
			).toThrow(/authorizationParams/);
		}
	});

	it("names the connection in every refusal, because an operator has more than one", () => {
		expect(() => resolve({ graph: { ...CONNECTION, boundary: "" } })).toThrow(/graph/);
	});
});
