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

// What a deployment must have configured before it may create grants (#593
// slice 6, D6–D8), resolved once at boot. Each refusal here is one a user
// would otherwise meet at the end of a consent, which is the worst place to
// find out that the deployment was never set up to finish it.

import {
	type FederatedIdentityRegistration,
	type FederationGrantConnection,
	InMemoryUserRepository,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	requireFederationGrantIdentityLookup,
	requireFederationGrantIntentStore,
	resolveFederationGrantAcquisitionSettings,
} from "#/acquisitionSettings.mjs";

const ISSUER = "https://auth.example.test";

const connection = (over: Partial<FederationGrantConnection> = {}): FederationGrantConnection => ({
	name: "calendar",
	federation: "upstream",
	upstreamIssuer: "https://issuer.example",
	upstreamClientId: "cid",
	scopes: ["openid", "offline_access"],
	boundary: "production",
	maxAccessTokenLifetime: 3600,
	callbackUri: `${ISSUER}/session/federation-grants/callback/calendar`,
	...over,
});

const resolve = (
	grants: Record<string, unknown>,
	connections: FederationGrantConnection[] = [connection()],
	issuer = ISSUER,
) =>
	resolveFederationGrantAcquisitionSettings(
		{
			oauth: { jwt: { issuer } },
			endpoints: { login: { url: "/login" } },
			federationGrants: grants,
		},
		new Map(connections.map((entry) => [entry.name, entry])),
	);

describe("resolveFederationGrantAcquisitionSettings", () => {
	it("resolves the consent page, the identity lookup and each connection's callback", () => {
		const settings = resolve({ consent: { url: "/consent/grants" } });
		expect(settings.consentUrl).toBe("/consent/grants");
		// Absent means required: the check it governs is a protection, and a
		// protection that is off unless someone asks for it is not one.
		expect(settings.identityLookup).toBe("required");
		expect(settings.origin).toBe(ISSUER);
		expect(settings.connections.get("calendar")?.callbackUri).toBe(
			`${ISSUER}/session/federation-grants/callback/calendar`,
		);
		expect(resolve({ consent: { url: "/c" }, identityLookup: "unsupported" }).identityLookup).toBe(
			"unsupported",
		);
	});

	it("refuses a deployment with no consent page: consent is the provider's own and is never skipped (D8)", () => {
		expect(() => resolve({})).toThrow(/federationGrants\.consent\.url/);
		expect(() => resolve({ consent: {} })).toThrow(/federationGrants\.consent\.url/);
		expect(() => resolve({ consent: { url: "" } })).toThrow(/federationGrants\.consent\.url/);
	});

	it("takes a consent page on the provider's own origin, and refuses one anywhere else", () => {
		// The page reads the consent data with the session cookie, and this
		// provider never answers a credentialed cross-origin read — so a page on
		// another origin could never show the user what they are agreeing to.
		expect(resolve({ consent: { url: `${ISSUER}/consent` } }).consentUrl).toBe(`${ISSUER}/consent`);
		for (const url of [
			"https://app.example.test/consent",
			"http://auth.example.test/consent",
			"//auth.example.test/consent",
			"javascript:alert(1)",
			"consent",
			`${ISSUER}/consent#fragment`,
			"/consent#fragment",
			// A path that normalises to another host (the adversarial review).
			"/.//evil.example/consent",
		]) {
			expect(() => resolve({ consent: { url } }), url).toThrow(/consent\.url/);
		}
	});

	it("refuses a deployment with no login page: connect sends a browser that is not signed in there", () => {
		expect(resolve({ consent: { url: "/c" } }).loginUrl).toBe("/login");
		for (const endpoints of [undefined, {}, { login: {} }, { login: { url: "" } }]) {
			expect(
				() =>
					resolveFederationGrantAcquisitionSettings(
						{
							oauth: { jwt: { issuer: ISSUER } },
							endpoints,
							federationGrants: { consent: { url: "/c" } },
						},
						new Map(),
					),
				JSON.stringify(endpoints),
			).toThrow(/endpoints\.login\.url/);
		}
	});

	it("refuses an issuer it cannot take an origin from", () => {
		// The origin every consent page and callback is held to is the issuer's.
		expect(() =>
			resolveFederationGrantAcquisitionSettings(
				{ oauth: { jwt: {} }, federationGrants: { consent: { url: "/c" } } },
				new Map(),
			),
		).toThrow(/oauth\.jwt\.issuer must be configured/);
		expect(() => resolve({ consent: { url: "/c" } }, [], "auth.example.test")).toThrow(
			/oauth\.jwt\.issuer must be an absolute URL/,
		);
	});

	it("refuses an identity lookup setting it would have to guess at", () => {
		expect(() => resolve({ consent: { url: "/c" }, identityLookup: "optional" })).toThrow(
			/identityLookup/,
		);
	});

	it("refuses a connection a grant could never be finished on", () => {
		// Without a callback of its own, the only place the upstream could send
		// the code is the LOGIN callback, which would treat it as a login.
		expect(() =>
			resolve({ consent: { url: "/c" } }, [connection({ callbackUri: undefined })]),
		).toThrow(/connections\.calendar\.callbackURL/);
		for (const callbackUri of [
			"https://elsewhere.example.test/session/federation-grants/callback/calendar",
			`${ISSUER}/session/oauth/federation/upstream/callback`,
			`${ISSUER}/session/federation-grants/callback/other-connection`,
			`${ISSUER}/session/federation-grants/callback/calendar?x=1`,
		]) {
			expect(
				() => resolve({ consent: { url: "/c" } }, [connection({ callbackUri })]),
				callbackUri,
			).toThrow(/callbackURL/);
		}
		// A deployment behind a path prefix keeps it in front of the route.
		expect(
			resolve({ consent: { url: "/c" } }, [
				connection({ callbackUri: `${ISSUER}/auth/session/federation-grants/callback/calendar` }),
			]).connections.size,
		).toBe(1);
	});
});

describe("requireFederationGrantIdentityLookup", () => {
	const connections = (...entries: FederationGrantConnection[]) =>
		new Map(entries.map((entry) => [entry.name, entry]));
	const unlinked = async () => ({ kind: "unlinked" as const });

	/** A Store written as a class, so a probe taken off the instance fails. */
	class Covering {
		readonly asked: FederatedIdentityRegistration[] = [];
		readonly claimsAsked: (readonly string[])[] = [];
		constructor(
			private readonly answer: (
				registration: FederatedIdentityRegistration,
				identityClaims: readonly string[],
			) => unknown,
		) {}
		supportsFederatedIdentityLookup(
			registration: FederatedIdentityRegistration,
			identityClaims: readonly string[],
		): boolean {
			this.asked.push({ ...registration });
			this.claimsAsked.push([...identityClaims]);
			return this.answer(registration, identityClaims) as boolean;
		}
		async findSubjectByFederatedIdentity() {
			return { kind: "unlinked" as const };
		}
	}

	it("refuses a required lookup the repository cannot answer, and says what to do", () => {
		for (const repository of [{}, undefined, { supportsFederatedIdentityLookup: () => true }]) {
			expect(() =>
				requireFederationGrantIdentityLookup("required", repository, connections(connection())),
			).toThrow(/findSubjectByFederatedIdentity[\s\S]*identityLookup = "unsupported"/);
		}
	});

	it("refuses a lookup that cannot say which registrations it covers (#611)", () => {
		expect(() =>
			requireFederationGrantIdentityLookup(
				"required",
				{ findSubjectByFederatedIdentity: unlinked },
				connections(connection()),
			),
		).toThrow(/supportsFederatedIdentityLookup/);
	});

	it("asks the Store about every connection's registration, through the Store, and boots when it covers them all", () => {
		const store = new Covering(() => true);
		expect(() =>
			requireFederationGrantIdentityLookup(
				"required",
				store,
				connections(
					connection(),
					connection({ name: "mail", federation: "entra-mail", upstreamClientId: "mail-client" }),
				),
			),
		).not.toThrow();
		expect(store.asked).toEqual([
			{ provider: "upstream", issuer: "https://issuer.example", clientId: "cid" },
			{ provider: "entra-mail", issuer: "https://issuer.example", clientId: "mail-client" },
		]);
	});

	it("refuses the one registration the Store does not cover, by connection and registration, with both remedies", () => {
		// D19's case: the login registration is covered, the grants one is not.
		const store = new Covering((registration) => registration.clientId !== "grants-client");
		let error: unknown;
		try {
			requireFederationGrantIdentityLookup(
				"required",
				store,
				connections(
					connection(),
					connection({
						name: "mail",
						federation: "entra-grants",
						upstreamClientId: "grants-client",
					}),
				),
			);
		} catch (caught) {
			error = caught;
		}
		const message = (error as Error | undefined)?.message ?? "";
		expect(message).toMatch(/connections\.mail/);
		expect(message).toMatch(/entra-grants/);
		expect(message).toMatch(/grants-client/);
		expect(message).toMatch(/identityLookup = "unsupported"/);
		expect(message).not.toMatch(/connections\.calendar/);
	});

	it("takes only a literal true as coverage: a truthy value, a promise or a throw refuses", () => {
		for (const answer of ["true", 1, {}, Promise.resolve(true), undefined, null, false]) {
			expect(
				() =>
					requireFederationGrantIdentityLookup(
						"required",
						new Covering(() => answer),
						connections(connection()),
					),
				String(answer),
			).toThrow(/connections\.calendar/);
		}
		// A probe that throws says so, and not what it threw: a Store's message
		// may carry the credentials it was connected with.
		let thrown: unknown;
		try {
			requireFederationGrantIdentityLookup(
				"required",
				new Covering(() => {
					throw new Error("directory offline at postgres://admin:hunter2@db");
				}),
				connections(connection()),
			);
		} catch (error) {
			thrown = error;
		}
		const message = (thrown as Error | undefined)?.message ?? "";
		expect(message).toMatch(/connections\.calendar[\s\S]*threw/);
		expect(message).not.toContain("hunter2");
		expect(message).not.toContain("directory offline");
	});

	it("tells the Store which claims each connection will hand it, connection by connection, even on one registration (#611)", () => {
		// A directory keyed by tenant and object id covers a registration only
		// when both are named; the same registration configured without them
		// on another connection is refused, not covered by its neighbour.
		const store = new Covering(
			(_registration, claims) => claims.includes("oid") && claims.includes("tid"),
		);
		expect(() =>
			requireFederationGrantIdentityLookup(
				"required",
				store,
				connections(connection({ identityClaims: ["oid", "tid"] }), connection({ name: "bare" })),
			),
		).toThrow(/connections\.bare/);
		expect(store.claimsAsked).toEqual([["oid", "tid"], []]);
	});

	it("refuses the bundled repository for any connection: it covers no registration", () => {
		const bundled = new InMemoryUserRepository(new Map());
		expect(() =>
			requireFederationGrantIdentityLookup("required", bundled, connections(connection())),
		).toThrow(/connections\.calendar[\s\S]*identityLookup = "unsupported"/);
	});

	it("probes nothing with no connection configured: removing the last one stays operable", () => {
		const store = new Covering(() => false);
		expect(() =>
			requireFederationGrantIdentityLookup("required", store, connections()),
		).not.toThrow();
		expect(store.asked).toEqual([]);
	});

	it("lets a deployment record that it has none — and then asks nothing of the repository", () => {
		const store = new Covering(() => false);
		expect(() =>
			requireFederationGrantIdentityLookup("unsupported", {}, connections(connection())),
		).not.toThrow();
		expect(() =>
			requireFederationGrantIdentityLookup("unsupported", store, connections(connection())),
		).not.toThrow();
		expect(store.asked).toEqual([]);
	});
});

describe("requireFederationGrantIntentStore", () => {
	it("refuses a deployment that could lodge an intent nowhere", () => {
		expect(() => requireFederationGrantIntentStore(undefined)).toThrow(
			/federationGrantIntentStore/,
		);
		const store = { kind: "memory" } as never;
		expect(requireFederationGrantIntentStore(store)).toBe(store);
	});
});
