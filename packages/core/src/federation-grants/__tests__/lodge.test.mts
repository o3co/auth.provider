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

import { beforeEach, describe, expect, it } from "vitest";
import {
	createMemoryFederationGrantIntentStore,
	type MemoryFederationGrantIntentStore,
} from "#/federation-grants/intentMemory.mjs";
import {
	FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT,
	FEDERATION_GRANT_FLOW_BUDGET_MS,
	type FederationGrantIntentStore,
} from "#/federation-grants/intentStore.mjs";
import {
	type FederationGrantAcquisitionConnection,
	type FederationGrantLodgingDeps,
	federationGrantRedirectUriReservedParameter,
	lodgeFederationGrantIntent,
	lodgeFederationGrantReauthorization,
} from "#/federation-grants/lodge.mjs";
import {
	createMemoryFederationGrantStore,
	type MemoryFederationGrantStore,
} from "#/federation-grants/memory.mjs";
import {
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
} from "#/federation-grants/revision.mjs";
import type { FederationGrantStore } from "#/federation-grants/store.mjs";
import type { FederationGrantIneligibilityReason } from "#/federation-grants/types.mjs";

const MIN = 60_000;
const DAY = 86_400_000;

const CONNECTION: FederationGrantAcquisitionConnection = {
	name: "okta-calendar",
	federation: "okta",
	upstreamIssuer: "https://dev-1.okta.test",
	upstreamClientId: "okta-client",
	scopes: ["openid", "offline_access", "calendar.read", "calendar.write"],
	boundary: "production",
	maxAccessTokenLifetime: 3600,
	callbackUri: "https://provider.test/session/federation-grants/callback/okta-calendar",
	authorizationParams: { access_type: "offline" },
};

const CLIENT = {
	clientId: "agent",
	allowedFederationGrantConnections: ["okta-calendar", "retired"],
	federationGrantRedirectUris: ["https://client.test/connected"],
};

const LIMITS = { defaultLifetimeMs: 30 * DAY, maxLifetimeMs: 90 * DAY };

/**
 * The injected clock sits on the real one: the memory stores reclaim on their
 * own clock (`Date.now()`), and a fixture dated in the past would be swept
 * before the test reads it.
 */
let T0 = new Date();
const at = (ms: number): Date => new Date(T0.getTime() + ms);

let grants: MemoryFederationGrantStore;
let intents: MemoryFederationGrantIntentStore;
let ids: number;
let clock: Date;

const deps = (over: Partial<FederationGrantLodgingDeps> = {}): FederationGrantLodgingDeps => ({
	grantStore: grants,
	intentStore: intents,
	connections: new Map([[CONNECTION.name, CONNECTION]]),
	limits: LIMITS,
	now: () => clock,
	randomId: () => {
		ids += 1;
		return `id-${ids}`;
	},
	grantsRevokedBefore: async () => null,
	revocationSkewMs: 1000,
	maxExpiresInMs: 90 * DAY,
	...over,
});

const initial = (over: Record<string, unknown> = {}) => ({
	client: CLIENT,
	connection: "okta-calendar",
	subject: "u-1",
	redirectUri: "https://client.test/connected",
	clientState: "client-state-1",
	correlationId: "corr-1",
	...over,
});

beforeEach(() => {
	T0 = new Date(Math.floor(Date.now() / 1000) * 1000 + 137);
	clock = T0;
	grants = createMemoryFederationGrantStore();
	intents = createMemoryFederationGrantIntentStore();
	ids = 0;
});

describe("lodging a first-time intent (D6, D16)", () => {
	it("admits the intent, then creates the pending grant naming it, and answers with both", async () => {
		const result = await lodgeFederationGrantIntent(deps(), initial());
		expect(result).toEqual({
			ok: true,
			grantId: "id-1",
			handle: "id-2",
			intentExpiresAt: at(FEDERATION_GRANT_FLOW_BUDGET_MS),
			lifetimeMs: 30 * DAY,
			connection: "okta-calendar",
			scopes: CONNECTION.scopes,
		});

		const intent = await intents.getIntent("id-2", at(MIN));
		expect(intent).toEqual({
			handle: "id-2",
			kind: "initial",
			grantId: "id-1",
			clientId: "agent",
			subject: "u-1",
			connection: "okta-calendar",
			federation: "okta",
			// Pinned now, so the callback decides against what the user will be
			// shown and not against configuration as it stands ten minutes later.
			identityRevision: federationGrantIdentityRevision(CONNECTION),
			authorizationRevision: federationGrantAuthorizationRevision(CONNECTION),
			callbackUri: CONNECTION.callbackUri,
			scopes: CONNECTION.scopes,
			authorizationParams: { access_type: "offline" },
			redirectUri: "https://client.test/connected",
			clientState: "client-state-1",
			lifetimeMs: 30 * DAY,
			createdAt: T0,
			expiresAt: at(FEDERATION_GRANT_FLOW_BUDGET_MS),
			correlationId: "corr-1",
		});
		expect(await grants.isCurrentIntent("id-1", "id-2", at(MIN))).toBe(true);
		expect((await grants.find("id-1", at(MIN)))?.status).toBe("pending");
	});

	it("carries the connection's resource and the client's upstream expectation", async () => {
		const withResource = { ...CONNECTION, resource: "https://api.example.test" };
		const result = await lodgeFederationGrantIntent(
			deps({ connections: new Map([[CONNECTION.name, withResource]]) }),
			initial({ upstreamSubject: "00u-alice" }),
		);
		expect(result.ok).toBe(true);
		const intent = await intents.getIntent("id-2", at(MIN));
		expect(intent?.resource).toBe("https://api.example.test");
		expect(intent?.upstreamSubject).toBe("00u-alice");
	});

	it("judges the client's permission before it says whether the connection exists", async () => {
		// A connection the client may not use is refused the same way whether or
		// not it is configured: which connections a deployment has is not
		// something a client can probe for.
		for (const connection of ["okta-calendar", "no-such-connection"]) {
			expect(
				await lodgeFederationGrantIntent(
					deps(),
					initial({ connection, client: { ...CLIENT, allowedFederationGrantConnections: [] } }),
				),
			).toEqual({ ok: false, reason: "connection_not_permitted" });
		}
		// Permitted, and gone from the configuration.
		expect(await lodgeFederationGrantIntent(deps(), initial({ connection: "retired" }))).toEqual({
			ok: false,
			reason: "connection_not_configured",
		});
		expect(intents.size).toBe(0);
	});

	it("reads the client's registration as a list or as nothing: a repository answering a string is not a substring match", async () => {
		// A deployment's own `ClientRepository` validates nothing this code can
		// see. Read with a bare `.includes`, a comma-joined string would let
		// "okta-calendar-prod" permit "okta-calendar" — the rule the token
		// route already applies (D9), applied at lodging too.
		const asString = (value: string) => value as unknown as readonly string[];
		expect(
			await lodgeFederationGrantIntent(
				deps(),
				initial({
					connection: "okta-calendar",
					client: { ...CLIENT, allowedFederationGrantConnections: asString("okta-calendar-prod") },
				}),
			),
		).toEqual({ ok: false, reason: "connection_not_permitted" });
		expect(
			await lodgeFederationGrantIntent(
				deps(),
				initial({
					client: {
						...CLIENT,
						federationGrantRedirectUris: asString("https://client.test/connected"),
					},
				}),
			),
		).toEqual({ ok: false, reason: "redirect_uri_not_registered" });
	});

	it("takes the redirect URI only by exact membership, and never one that would carry two answers", async () => {
		for (const redirectUri of [
			"https://client.test/connected/",
			"https://client.test/connected?x=1",
			"https://client.test/connect",
		]) {
			expect(await lodgeFederationGrantIntent(deps(), initial({ redirectUri }))).toEqual({
				ok: false,
				reason: "redirect_uri_not_registered",
			});
		}
		const registered = {
			...CLIENT,
			federationGrantRedirectUris: ["https://client.test/cb?state=x"],
		};
		expect(
			await lodgeFederationGrantIntent(
				deps(),
				initial({ client: registered, redirectUri: "https://client.test/cb?state=x" }),
			),
		).toEqual({ ok: false, reason: "redirect_uri_reserved_parameter" });
		expect(intents.size).toBe(0);
	});

	it("refuses a registered redirect URI that registration itself would have refused", async () => {
		// A repository that validates nothing can hand one back; the flow would
		// otherwise fail only at its end, after the grant was activated.
		const client = { ...CLIENT, federationGrantRedirectUris: ["not a uri"] };
		expect(
			await lodgeFederationGrantIntent(deps(), initial({ client, redirectUri: "not a uri" })),
		).toEqual({ ok: false, reason: "redirect_uri_invalid" });
		expect(intents.size).toBe(0);
	});

	it("holds the scopes to the connection and names what was wrong", async () => {
		const scoped = (scopes: readonly string[], connection = CONNECTION) =>
			lodgeFederationGrantIntent(
				deps({ connections: new Map([[CONNECTION.name, connection]]) }),
				initial({ scopes }),
			);
		expect(await scoped(["openid", "offline_access", "admin"])).toEqual({
			ok: false,
			reason: "scope_exceeded",
		});
		expect(await scoped(["offline_access", "calendar.read"])).toEqual({
			ok: false,
			reason: "openid_required",
		});
		expect(await scoped(["openid", "calendar.read"])).toEqual({
			ok: false,
			reason: "offline_access_required",
		});
		expect(
			await scoped(["openid", "offline_access"], { ...CONNECTION, allowScopeSubsets: false }),
		).toEqual({ ok: false, reason: "scope_subsets_not_allowed" });

		const narrowed = await scoped(["calendar.read", "openid", "offline_access"]);
		expect(narrowed.ok).toBe(true);
		// In the connection's order, whatever order the client wrote them in.
		expect((await intents.getIntent(narrowed.ok ? narrowed.handle : "", at(MIN)))?.scopes).toEqual([
			"openid",
			"offline_access",
			"calendar.read",
		]);
	});

	it("gives the default lifetime, clamps a request to the maximum, and refuses one that is not a duration", async () => {
		const asked = async (requestedLifetimeMs?: number) => {
			const result = await lodgeFederationGrantIntent(deps(), initial({ requestedLifetimeMs }));
			return result.ok ? result.lifetimeMs : result.reason;
		};
		expect(await asked()).toBe(30 * DAY);
		expect(await asked(DAY)).toBe(DAY);
		expect(await asked(365 * DAY)).toBe(90 * DAY);
		for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(await asked(bad)).toBe("expires_in_out_of_range");
		}
	});

	it("admits the intent BEFORE the grant, so a full bound creates no pending record", async () => {
		for (let i = 0; i < FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT; i += 1) {
			expect((await lodgeFederationGrantIntent(deps(), initial())).ok).toBe(true);
		}
		const grantsBefore = grants.size;
		expect(await lodgeFederationGrantIntent(deps(), initial())).toEqual({
			ok: false,
			reason: "intent_limit",
		});
		// The order is the point: had the grant been written first, every refused
		// admission would still have left a pending record behind.
		expect(grants.size).toBe(grantsBefore);
	});

	it("closes the intent when the grant store refuses the second write", async () => {
		const refusing: FederationGrantStore = {
			...grants,
			createPending: async () => ({ ok: false }),
		};
		expect(await lodgeFederationGrantIntent(deps({ grantStore: refusing }), initial())).toEqual({
			ok: false,
			reason: "storage",
		});
		expect(intents.holdsIntent("id-2")).toBe(true);
		expect(await intents.getIntent("id-2", at(MIN))).toBeNull();
		expect(intents.reservations("agent", "u-1")).toBe(0);
	});

	it("keeps an ambiguous second write that did happen, rather than undoing it", async () => {
		// The write landed and its answer was lost. Undoing it would destroy a
		// flow that may already be on its way to the user.
		const lost: FederationGrantStore = {
			...grants,
			createPending: async (input) => {
				await grants.createPending(input);
				throw new Error("connection reset");
			},
		};
		const result = await lodgeFederationGrantIntent(deps({ grantStore: lost }), initial());
		expect(result).toMatchObject({ ok: true, grantId: "id-1", handle: "id-2" });
		expect(await grants.isCurrentIntent("id-1", "id-2", at(MIN))).toBe(true);
	});

	it("reports an ambiguous second write that did not happen as an outage, and closes the intent", async () => {
		const failing: FederationGrantStore = {
			...grants,
			createPending: async () => {
				throw new Error("connection reset");
			},
		};
		expect(await lodgeFederationGrantIntent(deps({ grantStore: failing }), initial())).toEqual({
			ok: false,
			reason: "storage",
		});
		expect(await intents.getIntent("id-2", at(MIN))).toBeNull();
	});

	it("reports an intent store that cannot answer as an outage, and writes no grant", async () => {
		const down: FederationGrantIntentStore = {
			...intents,
			putIntent: async () => {
				throw new Error("down");
			},
		};
		expect(await lodgeFederationGrantIntent(deps({ intentStore: down }), initial())).toEqual({
			ok: false,
			reason: "storage",
		});
		expect(grants.size).toBe(0);
	});

	it("samples the time for the second write, not once for the whole request", async () => {
		let calls = 0;
		const seen: Date[] = [];
		const watching: FederationGrantStore = {
			...grants,
			createPending: async (input) => {
				seen.push(input.now);
				return await grants.createPending(input);
			},
		};
		await lodgeFederationGrantIntent(
			deps({
				grantStore: watching,
				now: () => {
					calls += 1;
					return at(calls * 10);
				},
			}),
			initial(),
		);
		expect(calls).toBeGreaterThanOrEqual(2);
		expect(seen[0]?.getTime()).toBeGreaterThan(T0.getTime() + 10);
	});
});

describe("federationGrantRedirectUriReservedParameter", () => {
	it("names the result parameter a registered redirect URI already carries", () => {
		expect(federationGrantRedirectUriReservedParameter("https://c.test/cb")).toBeUndefined();
		expect(federationGrantRedirectUriReservedParameter("https://c.test/cb?x=1")).toBeUndefined();
		expect(federationGrantRedirectUriReservedParameter("https://c.test/cb?state=a")).toBe("state");
		expect(federationGrantRedirectUriReservedParameter("https://c.test/cb?a=1&grant_id=")).toBe(
			"grant_id",
		);
		expect(federationGrantRedirectUriReservedParameter("https://c.test/cb?error=x")).toBe("error");
		expect(federationGrantRedirectUriReservedParameter("not a url")).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// Reauthorization
// ---------------------------------------------------------------------------

/** An `active` grant on the connection, consented at `consentAt`. */
const establish = async (
	consentAt = at(MIN),
	over: { subject?: string; clientId?: string } = {},
) => {
	await grants.createPending({
		id: "g-est",
		subject: over.subject ?? "u-1",
		clientId: over.clientId ?? "agent",
		connection: CONNECTION.name,
		intent: { handle: "h-est", expiresAt: at(FEDERATION_GRANT_FLOW_BUDGET_MS) },
		now: T0,
	});
	const written = await grants.activate({
		grantId: "g-est",
		intentHandle: "h-est",
		authorization: {
			identityRevision: federationGrantIdentityRevision(CONNECTION),
			authorizationRevision: federationGrantAuthorizationRevision(CONNECTION),
			upstream: { issuer: CONNECTION.upstreamIssuer, subject: "00u-alice" },
			scopes: ["openid", "offline_access", "calendar.read"],
			consent: {
				at: consentAt,
				sid: "sid-1",
				scopes: ["openid", "offline_access", "calendar.read"],
			},
			authorizedAt: new Date(consentAt.getTime() + 1000),
			expiresAt: new Date(consentAt.getTime() + 30 * DAY),
		},
		credentials: {
			refreshToken: "rt-1",
			accessToken: {
				value: "at-1",
				tokenType: "Bearer",
				obtainedAt: new Date(consentAt.getTime() + 1000),
				issuedLifetime: 3600,
				scopes: ["openid", "offline_access", "calendar.read"],
			},
		},
		now: new Date(consentAt.getTime() + 1000),
	});
	expect(written.ok).toBe(true);
};

const renewal = (over: Record<string, unknown> = {}) => ({
	client: CLIENT,
	grantId: "g-est",
	subject: "u-1",
	redirectUri: "https://client.test/connected",
	clientState: "client-state-2",
	correlationId: "corr-2",
	...over,
});

describe("lodging a reauthorization (D6, D13)", () => {
	beforeEach(() => {
		clock = at(2 * MIN);
	});

	it("names a new intent on the existing grant and changes nothing a client can see", async () => {
		await establish();
		const before = await grants.find("g-est", at(2 * MIN));
		const result = await lodgeFederationGrantReauthorization(deps(), renewal());
		expect(result).toEqual({
			ok: true,
			grantId: "g-est",
			handle: "id-1",
			intentExpiresAt: at(2 * MIN + FEDERATION_GRANT_FLOW_BUDGET_MS),
			lifetimeMs: 30 * DAY,
			connection: "okta-calendar",
			scopes: CONNECTION.scopes,
			status: "active",
		});
		expect(await grants.isCurrentIntent("g-est", "id-1", at(3 * MIN))).toBe(true);
		expect(await grants.find("g-est", at(3 * MIN))).toEqual(before);
		expect((await intents.getIntent("id-1", at(3 * MIN)))?.kind).toBe("reauthorization");
		// A renewal takes no place against the bound.
		expect(intents.reservations("agent", "u-1")).toBe(0);
	});

	it("answers one way for an unknown grant, another client's, and another subject's", async () => {
		await establish(at(MIN), { clientId: "someone-else" });
		for (const request of [
			renewal({ grantId: "nobody" }),
			renewal(),
			renewal({ subject: "u-2", client: { ...CLIENT, clientId: "someone-else" } }),
		]) {
			expect(await lodgeFederationGrantReauthorization(deps(), request)).toEqual({
				ok: false,
				reason: "grant_not_found",
			});
		}
		expect(intents.size).toBe(0);
	});

	it("revokes, durably, a grant the subject-wide boundary covers — before anything else is asked of it", async () => {
		await establish(at(MIN));
		// The client lost its permission too, and the request is malformed:
		// neither may hide a revocation that has to be written down.
		const result = await lodgeFederationGrantReauthorization(
			deps({ grantsRevokedBefore: async () => at(MIN + 500) }),
			renewal({
				client: { ...CLIENT, allowedFederationGrantConnections: [] },
				redirectUri: "https://evil.test/",
			}),
		);
		expect(result).toMatchObject({
			ok: false,
			reason: "grant_revoked",
			revokedBy: "backstop",
			revokedNow: true,
			// The record the write returned, so the audit describes what ended.
			revoked: { id: "g-est", status: "revoked" },
		});
		const grant = await grants.find("g-est", at(3 * MIN));
		expect(grant?.status).toBe("revoked");
		expect(intents.size).toBe(0);

		// Twice: the second call finds it revoked and changed nothing.
		expect(
			await lodgeFederationGrantReauthorization(
				deps({ grantsRevokedBefore: async () => at(MIN + 500) }),
				renewal(),
			),
		).toEqual({ ok: false, reason: "grant_revoked", revokedBy: "backstop", revokedNow: false });
	});

	it("claims the backstop revocation only when this call wrote it", async () => {
		// Found by mutation. Somebody else revoked the grant between this call's
		// read and its write: the write changes nothing, and reporting it as this
		// call's own would audit one revocation twice.
		await establish(at(MIN));
		const beaten: FederationGrantStore = {
			...grants,
			revoke: async (id, _by, when) => {
				await grants.revoke(id, "operator", when);
				return await grants.revoke(id, "backstop", when);
			},
		};
		expect(
			await lodgeFederationGrantReauthorization(
				deps({ grantStore: beaten, grantsRevokedBefore: async () => at(MIN + 500) }),
				renewal(),
			),
		).toEqual({ ok: false, reason: "grant_revoked", revokedBy: "backstop", revokedNow: false });
	});

	it("answers a key missing from the ring as an outage, not as a reason to consent again", async () => {
		// Found by mutation. The credential does not open because its key is not
		// in the ring — an operator's outage — and sending the user through
		// consent would not bring the key back.
		await establish();
		const keyless: FederationGrantStore = {
			...grants,
			inspect: async (id, when) => {
				const found = await grants.inspect(id, when);
				return found === null ? null : { ...found, credentials: "key_unavailable" };
			},
		};
		expect(
			await lodgeFederationGrantReauthorization(deps({ grantStore: keyless }), renewal()),
		).toEqual({
			ok: false,
			reason: "key_unavailable",
		});
		// A credential that is merely unreadable is exactly what renewal mends.
		const unreadable: FederationGrantStore = {
			...grants,
			inspect: async (id, when) => {
				const found = await grants.inspect(id, when);
				return found === null ? null : { ...found, credentials: "unreadable" };
			},
		};
		expect(
			await lodgeFederationGrantReauthorization(deps({ grantStore: unreadable }), renewal()),
		).toMatchObject({ ok: true, status: "reauthorization_required" });
	});

	it("fails closed on a boundary it cannot read, and leaves the grant alone", async () => {
		await establish();
		for (const broken of [
			async () => {
				throw new Error("down");
			},
			async () => new Date(Number.NaN),
			async () => "yesterday" as unknown as Date,
		]) {
			expect(
				await lodgeFederationGrantReauthorization(deps({ grantsRevokedBefore: broken }), renewal()),
			).toEqual({ ok: false, reason: "storage" });
		}
		expect((await grants.find("g-est", at(3 * MIN)))?.status).toBe("active");
	});

	it("refuses what a reauthorization cannot mend, each for its own reason", async () => {
		await establish();
		// Expired: the operator's maximum has passed.
		expect(
			await lodgeFederationGrantReauthorization(deps({ maxExpiresInMs: MIN / 2 }), renewal()),
		).toEqual({ ok: false, reason: "grant_expired", expiredBy: "operator_maximum" });
		// The upstream identity moved.
		expect(
			await lodgeFederationGrantReauthorization(
				deps({
					connections: new Map([
						[CONNECTION.name, { ...CONNECTION, upstreamClientId: "another-client" }],
					]),
				}),
				renewal(),
			),
		).toEqual({ ok: false, reason: "connection_identity_changed" });
		// The connection is gone.
		expect(
			await lodgeFederationGrantReauthorization(deps({ connections: new Map() }), renewal()),
		).toEqual({ ok: false, reason: "connection_not_configured" });
		// No token could ever satisfy the connection's maximum.
		expect(
			await lodgeFederationGrantReauthorization(
				deps({
					connections: new Map([[CONNECTION.name, { ...CONNECTION, maxAccessTokenLifetime: 0 }]]),
				}),
				renewal(),
			),
		).toEqual({
			ok: false,
			reason: "upstream_token_ineligible",
			ineligibleBy: "lifetime_over_maximum",
		});
		expect(intents.size).toBe(0);
	});

	/** The established grant, left ineligible by a refresh that answered a token nobody may use. */
	const starved = async (reason: FederationGrantIneligibilityReason) => {
		const grant = await grants.find("g-est", clock);
		const marked = await grants.replaceCredentials({
			grantId: "g-est",
			expectedVersion: grant?.version ?? -1,
			credentials: { refreshToken: "rt-1" },
			ineligible: { reason, at: clock, judgedAgainst: CONNECTION.maxAccessTokenLifetime },
			now: clock,
		});
		if (!marked.ok) throw new Error("fixture: the marker was not left");
		return marked.grant;
	};

	it("admits a grant starved of scope — a wider consent is exactly the remedy — and reports the ineligibility it does not change (#616)", async () => {
		await establish();
		const before = await starved("scope_exceeded");
		const result = await lodgeFederationGrantReauthorization(deps(), renewal());
		expect(result).toMatchObject({
			ok: true,
			grantId: "g-est",
			status: "upstream_token_ineligible",
		});
		expect(intents.size).toBe(1);
		// Lodging clears nothing: the marker, the credential and the version are
		// as they were. Only the callback's activation ends the starvation.
		expect(await grants.find("g-est", clock)).toMatchObject({
			version: before.version,
			ineligible: { reason: "scope_exceeded" },
		});
	});

	it("refuses every other ineligibility before an intent is lodged: a consent mends none of them (#616)", async () => {
		await establish();
		for (const reason of [
			"no_finite_lifetime",
			"token_type_unsupported",
			"malformed_token_response",
		] as const) {
			await starved(reason);
			expect(await lodgeFederationGrantReauthorization(deps(), renewal())).toEqual({
				ok: false,
				reason: "upstream_token_ineligible",
				ineligibleBy: reason,
			});
			expect(intents.size).toBe(0);
		}
	});

	it("judges the ineligibility as it reads now, not as the marker was left: a maximum no token can satisfy outranks an old scope marker (#616)", async () => {
		await establish();
		await starved("scope_exceeded");
		expect(
			await lodgeFederationGrantReauthorization(
				deps({
					connections: new Map([[CONNECTION.name, { ...CONNECTION, maxAccessTokenLifetime: 0 }]]),
				}),
				renewal(),
			),
		).toEqual({
			ok: false,
			reason: "upstream_token_ineligible",
			ineligibleBy: "lifetime_over_maximum",
		});
		expect(intents.size).toBe(0);
	});

	it("accepts a grant that needs reauthorization, which is what the route is for", async () => {
		await establish();
		const changed = { ...CONNECTION, scopes: [...CONNECTION.scopes, "contacts.read"] };
		const result = await lodgeFederationGrantReauthorization(
			deps({ connections: new Map([[CONNECTION.name, changed]]) }),
			renewal(),
		);
		expect(result).toMatchObject({ ok: true, status: "reauthorization_required" });
	});

	it("refuses a pending grant: a first intent makes a new grant and never takes over another", async () => {
		await grants.createPending({
			id: "g-est",
			subject: "u-1",
			clientId: "agent",
			connection: CONNECTION.name,
			intent: { handle: "h-est", expiresAt: at(FEDERATION_GRANT_FLOW_BUDGET_MS) },
			now: T0,
		});
		expect(await lodgeFederationGrantReauthorization(deps(), renewal())).toEqual({
			ok: false,
			reason: "authorization_pending",
		});
	});

	it("judges the client's current permission only once the grant could be renewed", async () => {
		await establish();
		expect(
			await lodgeFederationGrantReauthorization(
				deps(),
				renewal({ client: { ...CLIENT, allowedFederationGrantConnections: [] } }),
			),
		).toEqual({ ok: false, reason: "connection_not_permitted" });
	});

	it("reads the renewal's permission as a list or as nothing, as lodging does", async () => {
		await establish();
		expect(
			await lodgeFederationGrantReauthorization(
				deps(),
				renewal({
					client: {
						...CLIENT,
						allowedFederationGrantConnections:
							`${CONNECTION.name}-prod` as unknown as readonly string[],
					},
				}),
			),
		).toEqual({ ok: false, reason: "connection_not_permitted" });
	});

	it("refuses a connection the caller asserts that is not the grant's — an assertion, never a move", async () => {
		await establish();
		expect(
			await lodgeFederationGrantReauthorization(deps(), renewal({ connection: "another" })),
		).toEqual({ ok: false, reason: "connection_mismatch" });
		expect(
			await lodgeFederationGrantReauthorization(deps(), renewal({ connection: CONNECTION.name })),
		).toMatchObject({ ok: true });
	});

	it("validates the renewal's own request as a first intent's is validated", async () => {
		await establish();
		expect(
			await lodgeFederationGrantReauthorization(
				deps(),
				renewal({ redirectUri: "https://evil.test/" }),
			),
		).toEqual({ ok: false, reason: "redirect_uri_not_registered" });
		expect(
			await lodgeFederationGrantReauthorization(deps(), renewal({ scopes: ["openid", "admin"] })),
		).toEqual({ ok: false, reason: "scope_exceeded" });
	});

	it("re-reads the grant when the pointer write loses, and closes the intent it admitted", async () => {
		await establish();
		// Revoked between the read and the write: the write loses, and the
		// answer is what the grant is now — not a retry that renews it anyway.
		const racing: FederationGrantStore = {
			...grants,
			nameIntent: async (input) => {
				await grants.revoke("g-est", "operator", at(2 * MIN));
				return await grants.nameIntent(input);
			},
		};
		expect(
			await lodgeFederationGrantReauthorization(deps({ grantStore: racing }), renewal()),
		).toEqual({
			ok: false,
			reason: "grant_revoked",
			revokedBy: "operator",
			revokedNow: false,
		});
		expect(await intents.getIntent("id-1", at(3 * MIN))).toBeNull();
	});

	it("answers every grant-store call a renewal cannot make as an outage, never as a guess", async () => {
		await establish();
		const throwing = async () => {
			throw new Error("down");
		};
		// The first read, before anything is judged.
		expect(
			await lodgeFederationGrantReauthorization(
				deps({ grantStore: { ...grants, inspect: throwing } }),
				renewal(),
			),
		).toEqual({ ok: false, reason: "storage" });
		// The backstop's durable write.
		expect(
			await lodgeFederationGrantReauthorization(
				deps({
					grantStore: { ...grants, revoke: throwing },
					grantsRevokedBefore: async () => at(2 * MIN),
				}),
				renewal(),
			),
		).toEqual({ ok: false, reason: "storage" });
		expect((await grants.find("g-est", at(3 * MIN)))?.status).toBe("active");
		expect(intents.size).toBe(0);
	});

	it("asks whether a pointer write whose answer was lost landed, and keeps it when it did", async () => {
		await establish();
		const lost: FederationGrantStore = {
			...grants,
			nameIntent: async (input) => {
				await grants.nameIntent(input);
				throw new Error("connection reset");
			},
		};
		expect(
			await lodgeFederationGrantReauthorization(deps({ grantStore: lost }), renewal()),
		).toMatchObject({ ok: true, grantId: "g-est", handle: "id-1" });
		expect(await grants.isCurrentIntent("g-est", "id-1", at(3 * MIN))).toBe(true);
	});

	it("reads a lost pointer write it cannot confirm as not landed, and a grant it cannot re-read as an outage", async () => {
		await establish();
		const unconfirmed: FederationGrantStore = {
			...grants,
			nameIntent: async () => {
				throw new Error("connection reset");
			},
			isCurrentIntent: async () => {
				throw new Error("connection reset");
			},
		};
		// Still renewable when re-read: the honest answer is that this attempt did not take.
		expect(
			await lodgeFederationGrantReauthorization(deps({ grantStore: unconfirmed }), renewal()),
		).toEqual({ ok: false, reason: "storage" });
		expect(await intents.getIntent("id-1", at(3 * MIN))).toBeNull();

		let reads = 0;
		const unreadable: FederationGrantStore = {
			...unconfirmed,
			inspect: async (id, when) => {
				reads += 1;
				if (reads > 1) throw new Error("down");
				return await grants.inspect(id, when);
			},
		};
		expect(
			await lodgeFederationGrantReauthorization(deps({ grantStore: unreadable }), renewal()),
		).toEqual({ ok: false, reason: "storage" });
		expect(await intents.getIntent("id-2", at(3 * MIN))).toBeNull();
	});
});

describe("lodging without an id source of the caller's", () => {
	it("draws a 256-bit handle and grant id of its own", async () => {
		const result = await lodgeFederationGrantIntent(deps({ randomId: undefined }), initial());
		expect(result).toMatchObject({ ok: true });
		if (!result.ok) return;
		for (const id of [result.grantId, result.handle]) expect(id).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(result.grantId).not.toBe(result.handle);
	});
});
