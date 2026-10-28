import { createHash, randomBytes } from "node:crypto";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { type Grant, type GrantInput, grants, sessionIssuances, targetRules } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, takesUnused, unavailableSwitch } from "@mod/kernel/testing";
import { crowdingFor, memoryRecords } from "@mod/records/testing";
import secretHashModule from "@mod/secret-hash/module";
import { sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import sessionParticipants from "@mod/session-participants/module";
import { entryRequirements } from "@mod/session-requirements";
import sessionRequirements from "@mod/session-requirements/module";
import { sessionTokens } from "@mod/session-tokens";
import bridgeModule from "@mod/session-tokens/module";
import { sessionTokensInMemory } from "@mod/session-tokens/testing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { grantCaller, grantCalls, grantInput } from "@mod/token-endpoint/testing";
import { type IssuanceRequest, type IssuedAccess, issuancePolicies, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { afterEach, describe, expect, it } from "vitest";
import { fromStored } from "../src/codes.ts";
import {
	additions,
	type CodeFacts,
	type CodeStore,
	codeStore,
	codes,
	type IdTokenRequest,
	idTokens,
	type Redeemed,
	redemptionHooks,
	type StoredCode,
	sessionRedemptions,
	type VoidList,
	voidList,
} from "../src/contract.ts";
import codeGrantModule from "../src/module.ts";
import { codeGrantConfig, codeStoreContract } from "../src/testing.ts";

const grantsSeen = contract<readonly Grant[]>("grants-seen");

let shift = 0;
/** A copy of every draw of 32 bytes the composition made, in order, so a test can tell what a code was made from. */
const drawn: Uint8Array[] = [];
const runtime = quietRuntime({
	clock: { now: () => Date.now() + shift },
	random: {
		bytes: (n) => {
			const bytes = new Uint8Array(randomBytes(n));
			if (n === 32) drawn.push(bytes.slice());
			return bytes;
		},
	},
});
let stop = async () => {};
/** A code's name as a place might make it: not the code, so a test that peeks by code finds nothing. */
const nameOf = (code: string) => `n.${createHash("sha256").update(code).digest("base64url")}`;
/** code-grant's stores on the records stand-in, with its clock from the composition; the void list behind a switch. */
const memoryStores = () => {
	let clock = () => 0;
	const stand = memoryRecords<StoredCode>(() => clock(), { shards: 16, perShard: 100 });
	const voids = unavailableSwitch<VoidList>("void list");
	/** Whether the next change finds nothing, as a read that has not yet seen the record. */
	let missing = false;
	const update: CodeStore["update"] = (name, change) => {
		if (!missing) return stand.records.change(name, change);
		missing = false;
		return Promise.resolve(undefined);
	};
	const module = defineModule({ name: "code-stores", replicaSafe: false, takes: [] }, (m) => [
		m.provide(codeStore).by((c) => {
			clock = c.clock.now;
			return { nameOf, save: stand.records.create, update };
		}),
		m.provide(voidList).by(() => voids.wrap(stand.deferred)),
	]);
	return { module, ...stand, voids, missNextChange: () => (missing = true) };
};
afterEach(async () => {
	shift = 0;
	drawn.length = 0;
	await stop();
});

codeStoreContract("records stand-in", async () => {
	let now = 0;
	const size = { shards: 4, perShard: 5 };
	const stand = memoryRecords<StoredCode>(() => now, size);
	return {
		codes: { nameOf, save: stand.records.create, update: stand.records.change },
		voids: stand.deferred,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_name, change) => stand.raceNextChange(change),
		crowd: { limit: size.perShard, names: crowdingFor(size).jobs },
	};
});
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const maker = (scope: string) =>
	defineModule({ name: `maker-${scope}`, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(idTokens).by(() => ({ scope, make: async () => "id.token" })),
	]);
/** Hands the grants to the test, so it can call the code grant directly. */
const reader = defineModule({ name: "reader", replicaSafe: true, takes: [grants] }, (m) => [
	m.provide(grantsSeen).by((c) => c.collect(grants)),
]);

/** The same answer for every refused code, as the token endpoint sends it and as the grant gives it. */
const refusedBody = { error: "invalid_grant", error_description: "invalid code" };
const refusedOutcome = { kind: "error", error: "invalid_grant", description: "invalid code" };
/** A stored record with fields written over, as a broken or foreign writer might leave it. */
const overwritten = (kept: StoredCode, over: object) =>
	({ ...(kept as unknown as object), ...over }) as unknown as StoredCode;
/** Waits until the sweep, every second here, has run once. */
const afterSweep = () => new Promise((resolve) => setTimeout(resolve, 1300));
const refusedFor = (reason: string) =>
	expect.objectContaining({
		refusals: expect.arrayContaining([expect.objectContaining({ reason })]),
	});

/** A policy that allows what `allows` allows, and refuses the rest. */
const policy = (allows: (request: IssuanceRequest) => boolean) =>
	defineModule({ name: "test-policy", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(issuancePolicies).by(() => ({
			name: "test-policy",
			judge: async (request) =>
				allows(request)
					? { kind: "allowed" }
					: { kind: "refused", reason: "test_reason", description: "refused here" },
		})),
	]);

type Options = {
	revocation?: "denylist" | "unsupported";
	/** Whether session-tokens records the tokens issued from a session (as combinations composes it). */
	recorded?: boolean;
	extra?: Module[];
	codeGrant?: Parameters<typeof codeGrantConfig>[0];
};

/** What `serve` assembles, with the stores it reaches into. */
function assembly(options: Options = {}) {
	const stores = memoryStores();
	const input = {
		modules: [
			http,
			tokensStandIn({ revocable: (options.revocation ?? "denylist") === "denylist" }),
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			sessionStandIn,
			sessionParticipants,
			sessionRequirements,
			subjectRevocationStandIn,
			stores.module,
			...(options.recorded === false ? [] : [bridgeModule, sessionTokensInMemory().module]),
			codeGrantModule,
			reader,
			...(options.extra ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...issuerConfig({ url: "https://as.example" }),
			...clientsConfig(
				["app", "other"].map((id) =>
					confidentialClient({
						id,
						sections: allowancesFor({
							grants: ["authorization_code"],
							scopes: ["openid", "read"],
							audiences: ["https://api"],
						}),
					}),
				),
			),
			...codeGrantConfig(options.codeGrant ?? { "sweep-interval": "1s" }),
		},
		runtime,
	};
	return { input, stores };
}

async function serve(options: Options = {}) {
	const { input, stores } = assembly(options);
	const app = await assemble(input);
	await app.start();
	stop = () => app.stop(1000);
	const { session, cookies } = await app.get(sessions).complete(testRequest(), {
		subject: "alice",
		amr: ["pwd"],
		authenticatedAt: runtime.clock.now(),
	});
	const facts: CodeFacts = {
		clientId: "app",
		redirectUri: "https://app.example/cb",
		challenge,
		scope: ["read"],
		audience: ["https://api"],
		session: session.id,
		subject: "alice",
	};
	const issue = (scope = facts.scope) => app.get(codes).issue({ ...facts, scope });
	/** Redeems through the grant harness, answering as the token endpoint would. */
	const redeem = async (
		code: string,
		extra: Record<string, string> = {},
	): Promise<{ status: number; body: Record<string, unknown> }> => {
		const params = {
			grant_type: "authorization_code",
			code,
			redirect_uri: "https://app.example/cb",
			code_verifier: verifier,
			...extra,
		};
		const outcome = await app
			.get(grantCalls)
			.call("authorization_code", "app", params)
			.catch((error: unknown) => {
				if (isUnavailable(error)) return undefined;
				throw error;
			});
		if (!outcome) return { status: 503, body: { error: "temporarily_unavailable" } };
		if (outcome.kind === "issued") return { status: 200, body: { ...outcome.body } };
		const described = outcome.description ? { error_description: outcome.description } : {};
		return { status: 400, body: { error: outcome.error, ...described } };
	};
	return { app, stores, issue, redeem, session, cookies, facts };
}
/** A request carrying the session cookies given. */
const carrying = (setCookies: readonly string[]) =>
	testRequest({
		headers: new Map([["cookie", setCookies.map((c) => c.split(";")[0]).join("; ")]]),
		source: { scheme: "https" },
	});
type Served = Awaited<ReturnType<typeof serve>>;
/** What a code's record holds now. */
const keptOf = (s: Served, code: string) => {
	const kept = s.stores.peek(nameOf(code));
	return kept && fromStored(kept);
};

const revoked = async (s: Served, token: string) =>
	(await s.app.get(tokens).verifyAccess(token)).kind === "invalid";
const directClient = {
	id: "app",
	kind: "confidential" as const,
	method: "client_secret_post",
	registered: true,
	section: <T>() => ({}) as T,
};
/** Calls the grant directly, so a test can step into the token's issuing or hand it a binding. */
async function handleDirectly(
	s: Served,
	code: string,
	over: Partial<Pick<GrantInput, "issue" | "binding">> = {},
) {
	const grant = s.app.get(grantsSeen).find((g) => g.grantType === "authorization_code");
	const params: Record<string, string> = {
		code,
		redirect_uri: "https://app.example/cb",
		code_verifier: verifier,
	};
	if (!grant) throw new Error("no authorization_code grant");
	return grant.handle({ ...grantInput(s.app.get(tokens), grant, directClient, params), ...over });
}

it("gives the access token the code's amr, authentication time and acr, issued from its session", async () => {
	const asked: IssuanceRequest[] = [];
	const s = await serve({ extra: [policy((request) => asked.push(request) > 0)] });
	const code = await s.app.get(codes).issue({ ...s.facts, acr: "urn:example:acr:high" });
	const answer = await s.redeem(code);
	const checked = await s.app.get(tokens).verifyAccess(String(answer.body.access_token));
	const { authenticatedAt } = s.session.context;
	expect(checked).toMatchObject({
		kind: "valid",
		grant: {
			amr: ["pwd"],
			authenticatedAt: Math.floor(authenticatedAt / 1000) * 1000,
			acr: "urn:example:acr:high",
		},
	});
	expect(asked.map((request) => [request.grantType, request.session])).toEqual([
		["authorization_code", s.session.id],
		["authorization_code", s.session.id],
	]);
});

it("issues for the code's subject, session and login as they were when it was issued, whatever session the exchange carries", async () => {
	const s = await serve();
	const code = await s.issue();
	const all = s.app.get(sessions);
	expect(await all.raise(carrying(s.cookies), ["otp"])).toBeDefined();
	const bob = await all.complete(testRequest(), {
		subject: "bob",
		amr: ["pwd", "otp"],
		authenticatedAt: runtime.clock.now(),
	});
	const params = {
		grant_type: "authorization_code",
		code,
		redirect_uri: "https://app.example/cb",
		code_verifier: verifier,
	};
	const outcome = await s.app
		.get(grantCalls)
		.call("authorization_code", "app", params, { request: carrying(bob.cookies) });
	if (outcome.kind !== "issued") throw new Error(outcome.kind);
	const checked = await s.app.get(tokens).verifyAccess(String(outcome.body.access_token));
	if (checked.kind !== "valid") throw new Error("not valid");
	expect(checked.grant).toMatchObject({ subject: "alice", amr: ["pwd"] });
	expect(await s.app.get(sessionTokens).sessionOf(checked.id)).toEqual({
		kind: "bound",
		handle: s.session.id,
	});
});

it("has the access token recorded to the code's session", async () => {
	const s = await serve();
	const answer = await s.redeem(await s.issue());
	const checked = await s.app.get(tokens).verifyAccess(String(answer.body.access_token));
	if (checked.kind !== "valid") throw new Error("not valid");
	expect(await s.app.get(sessionTokens).sessionOf(checked.id)).toEqual({
		kind: "bound",
		handle: s.session.id,
	});
});

it("revokes the code's access token when its session closes, through session-tokens' participant", async () => {
	const s = await serve();
	const token = String((await s.redeem(await s.issue())).body.access_token);
	expect(await revoked(s, token)).toBe(false);
	await s.app.get(sessions).close(s.session.id, carrying(s.cookies));
	expect(await revoked(s, token)).toBe(true);
});

it("ends the access token no later than its session, when the session ends first [rfc6749-5.1-b]", async () => {
	const s = await serve();
	const entry = await s.app.get(sessions).entryOf(s.session.id);
	if (entry.kind !== "entered") throw new Error("not entered");
	const { endsAt } = entry;
	shift = 3_000_000;
	const answer = await s.redeem(await s.issue());
	const checked = await s.app.get(tokens).verifyAccess(String(answer.body.access_token));
	if (checked.kind !== "valid") throw new Error("not valid");
	expect(checked.expiresAt).toBeLessThanOrEqual(endsAt);
	expect(Number(answer.body.expires_in)).toBeLessThanOrEqual(600);
});

it("refuses a code whose session authenticated far ahead of the clock, leaving it unused", async () => {
	shift = 400_000;
	const s = await serve();
	const code = await s.issue();
	shift = 0;
	const answer = await s.redeem(code);
	expect([answer.status, answer.body.error]).toEqual([400, "invalid_grant"]);
	expect(answer.body.error_description).not.toBe("invalid code");
	expect(keptOf(s, code)?.state).toBe("issued");
});

it("asks the issuance policies before the code is used up, and only for its own client and verifier [rfc7636-4.6-b]", async () => {
	const s = await serve({ extra: [policy(() => false)] });
	const code = await s.issue();
	const refused = { error: "invalid_grant", error_description: "refused here" };
	expect((await s.redeem(code)).body).toEqual(refused);
	expect(keptOf(s, code)?.state).toBe("issued");
	// A wrong verifier is told nothing of the policies, and uses the code up.
	expect((await s.redeem(code, { code_verifier: "w".repeat(43) })).body).toEqual(refusedBody);
	expect(keptOf(s, code)?.state).toBe("consumed");
});

/** A rule narrowing to the `resource` asked when the issuance may have it, as resource indicators do. */
const narrowing = defineModule({ name: "narrowing", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(targetRules).by(() => ({
		target: ({ param, audience, within }) => {
			const asked = param("resource");
			if (!asked) return { kind: "audience", audience };
			return within(asked)
				? { kind: "audience", audience: [asked] }
				: { kind: "error", error: "invalid_target", description: `not ${asked}` };
		},
	})),
]);

it("refuses a resource outside the code's audience before the code is used up, and redeems it after", async () => {
	const s = await serve({ extra: [narrowing] });
	const code = await s.issue();
	expect((await s.redeem(code, { resource: "https://other" })).body).toEqual({
		error: "invalid_target",
		error_description: "not https://other",
	});
	expect(keptOf(s, code)?.state).toBe("issued");
	expect((await s.redeem(code, { resource: "https://api" })).status).toBe(200);
});

it("refuses a resource outside the code's audience when the look before use missed the code, issuing nothing", async () => {
	const s = await serve({ extra: [narrowing] });
	const code = await s.issue();
	s.stores.missNextChange();
	expect((await s.redeem(code, { resource: "https://other" })).body).toEqual({
		error: "invalid_target",
		error_description: "not https://other",
	});
	expect(keptOf(s, code)?.token).toBeUndefined();
});

it("takes the resource the rule refuses to a grant that takes no audience, as one that asks it", async () => {
	const strict = defineModule({ name: "strict", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(targetRules).by(() => ({
			target: ({ param, audience, within }) => {
				const asked = param("resource");
				if (!asked) return { kind: "audience", audience };
				return within(asked)
					? { kind: "audience", audience: [asked] }
					: { kind: "error", error: "invalid_target", description: `not ${asked}` };
			},
			untargeted: ({ param }) =>
				param("resource")
					? { kind: "error", error: "invalid_target", description: "takes no resource" }
					: undefined,
		})),
	]);
	const s = await serve({ extra: [strict] });
	expect((await s.redeem(await s.issue(), { resource: "https://api" })).status).toBe(200);
});

it("reads no resource at the exchange where no rule is composed", async () => {
	const s = await serve();
	expect((await s.redeem(await s.issue(), { resource: "https://other" })).status).toBe(200);
});

it("refuses a code the policies refuse once it is used up, issuing nothing", async () => {
	let asks = 0;
	const s = await serve({ extra: [policy(() => ++asks < 2)] });
	const code = await s.issue();
	expect((await s.redeem(code)).body).toEqual({
		error: "invalid_grant",
		error_description: "refused here",
	});
	expect(keptOf(s, code)).toMatchObject({ state: "consumed" });
	expect(keptOf(s, code)?.token).toBeUndefined();
	expect((await s.redeem(code)).body).toEqual(refusedBody);
});

it("redeems a code once, and a code that comes again revokes what it gave [rfc6749-4.1.2-d] [rfc6749-4.1.2-e] [oidc-core-16.9-a]", async () => {
	const s = await serve();
	const code = await s.issue();
	const first = await s.redeem(code);
	expect(first.status).toBe(200);
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	expect(await revoked(s, String(first.body.access_token))).toBe(true);
});

it("keeps neither the code nor the token it gave in code-grant's own record of the code, the token noted by its reference and end alone [rfc6749-10.3-a]", async () => {
	const s = await serve();
	const code = await s.issue();
	const redeemed = await s.redeem(code);
	expect(redeemed.status).toBe(200);
	const stored = JSON.stringify(s.stores.peek(nameOf(code)));
	for (const secret of [code, String(redeemed.body.access_token)]) {
		expect(stored).not.toContain(secret);
	}
	expect(Object.keys(keptOf(s, code)?.token ?? {}).sort()).toEqual(["expiresAt", "reference"]);
});

it("refuses a code another exchange used up while this one was turning it, and lists and marks it void [rfc6749-4.1.2-d]", async () => {
	const s = await serve();
	const code = await s.issue();
	s.stores.raceNextChange((kept) => overwritten(kept, { state: "consumed" }));
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	expect(s.stores.pending()).toEqual([nameOf(code)]);
	const kept = s.stores.peek(nameOf(code));
	expect(kept && fromStored(kept)?.void).toBe(true);
});

it("refuses a code whose record is in a state or shape it does not know, however often it comes", async () => {
	const s = await serve();
	const odd = {
		"unknown state": { state: "pending" },
		"scope not a list": { scope: "read" },
		"another format": { format: 0 },
		"an unknown field": { kept: true },
	};
	for (const [label, over] of Object.entries(odd)) {
		const code = await s.issue();
		await s.stores.records.change(nameOf(code), (kept) => ({ value: overwritten(kept, over) }));
		for (const _ of [1, 2]) expect((await s.redeem(code)).body, label).toEqual(refusedBody);
	}
});

it("writes a code's record in format 2, and still redeems one a host before it wrote in format 1", async () => {
	const s = await serve();
	const code = await s.issue();
	expect(keptOf(s, code)?.format).toBe(2);
	await s.stores.records.change(nameOf(code), (kept) => ({
		value: overwritten(kept, { format: 1 }),
	}));
	expect((await s.redeem(code)).status).toBe(200);
});

it("drops a listed void whose record it does not know, as one it cannot revoke, at the next sweep", async () => {
	const s = await serve();
	const code = await s.issue();
	await s.stores.records.change(nameOf(code), (kept) => ({
		value: overwritten(kept, { state: "pending" }),
	}));
	await s.stores.deferred.add(nameOf(code));
	await afterSweep();
	expect(s.stores.pending()).toEqual([]);
});

it("refuses a request missing the code, the redirect URI or the verifier, a code or redirect URI sent empty as one left out, or with a malformed verifier, leaving the code unused [rfc6749-5.2-f] [rfc7636-4.5-b] [rfc6749-4.1.3-e] [rfc6749-3.2-b]", async () => {
	const s = await serve();
	const code = await s.issue();
	const cases: Record<string, Record<string, string>> = {
		"no code": { code: "" },
		"no redirect URI": { redirect_uri: "" },
		"no verifier": { code_verifier: "" },
		"a verifier too short": { code_verifier: "v".repeat(42) },
		"a verifier with a character outside its set": { code_verifier: `${"v".repeat(42)}+` },
	};
	for (const [name, extra] of Object.entries(cases)) {
		expect((await s.redeem(code, extra)).body.error, name).toBe("invalid_request");
	}
	expect(keptOf(s, code)?.state).toBe("issued");
	expect((await s.redeem(code)).status).toBe(200);
});

it("refuses a code whose subject was revoked after it signed in", async () => {
	const s = await serve();
	const code = await s.issue();
	shift = 1000;
	await s.app.get(revocations).record("alice");
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	expect(keptOf(s, code)?.token).toBeUndefined();
});
it("refuses a code issued to another client, or presented with another redirect URI [rfc6749-4.1.3-c] [rfc6749-4.1.3-e]", async () => {
	const s = await serve();
	const elsewhere = await s.app.get(codes).issue({ ...s.facts, clientId: "other" });
	expect((await s.redeem(elsewhere)).body).toEqual(refusedBody);
	const code = await s.issue();
	expect((await s.redeem(code, { redirect_uri: "https://app.example/other" })).body).toEqual(
		refusedBody,
	);
});

it("redeems a code issued for OpenID Connect only for its own client and redirect URI, only once and only while it lives [oidc-core-3.1.3.2-b] [oidc-core-3.1.3.2-c] [oidc-core-3.1.3.2-e]", async () => {
	const s = await serve({ codeGrant: { "code-lifetime": "10s", "sweep-interval": "1s" } });
	const oidc = ["openid", "read"];
	const elsewhere = await s.app.get(codes).issue({ ...s.facts, scope: oidc, clientId: "other" });
	expect((await s.redeem(elsewhere)).body).toEqual(refusedBody);
	const moved = await s.issue(oidc);
	expect((await s.redeem(moved, { redirect_uri: "https://app.example/other" })).body).toEqual(
		refusedBody,
	);
	expect((await s.redeem("not-a-code")).body).toEqual(refusedBody);
	const late = await s.issue(oidc);
	shift = 11_000;
	expect((await s.redeem(late)).body).toEqual(refusedBody);
	shift = 0;
	const code = await s.issue(oidc);
	const first = await s.redeem(code);
	expect([first.status, first.body.scope]).toEqual([200, "openid read"]);
	expect((await s.redeem(code)).body).toEqual(refusedBody);
});

it("issues nothing for a code whose session closed before the exchange", async () => {
	const s = await serve();
	const code = await s.issue();
	await s.app.get(sessions).close(s.session.id, carrying(s.cookies));
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	expect(keptOf(s, code)?.token).toBeUndefined();
});

/** A requirement a session falls short of at use while `short.now` is set. */
const shortToUse = (short: { now: boolean }) =>
	defineModule({ name: "short-to-use", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(entryRequirements).by(() => ({
			name: "mfa",
			judges: ["use"],
			admits: async () =>
				short.now ? { kind: "short", answer: { error: "mfa_required" } } : { kind: "admit" },
		})),
	]);

it("issues nothing for a code whose session falls short of a requirement to be used, as a closed one", async () => {
	const short = { now: false };
	const s = await serve({ extra: [shortToUse(short)] });
	const code = await s.issue();
	short.now = true;
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	expect(keptOf(s, code)?.token).toBeUndefined();
	await expect(s.app.get(codes).issue(s.facts), "a code for it").rejects.toThrow(Unavailable);
});

it("keeps an unused code for code-lifetime, and no longer [oidc-core-16.9-a]", async () => {
	const s = await serve({ codeGrant: { "code-lifetime": "10s" } });
	const code = await s.issue();
	shift = 9000;
	expect(keptOf(s, code)).toBeDefined();
	shift = 11_000;
	expect(keptOf(s, code)).toBeUndefined();
});

it("keeps a redeemed code's record past its token's end by the allowance for clock drift", async () => {
	const s = await serve();
	const code = await s.issue();
	const answer = await s.redeem(code);
	const checked = await s.app.get(tokens).verifyAccess(String(answer.body.access_token));
	if (checked.kind !== "valid") throw new Error("not valid");
	shift = checked.expiresAt - Date.now() + 60_000;
	expect(keptOf(s, code)?.token).toBeDefined();
	shift = checked.expiresAt - Date.now() + 130_000;
	expect(keptOf(s, code)).toBeUndefined();
});

it("voids the token it issued when the code is used again while the token is made", async () => {
	const s = await serve();
	const code = await s.issue();
	const given: string[] = [];
	const answer = await handleDirectly(s, code, {
		issue: async (g) => {
			const issued = await s.app.get(tokens).issue({ grant: g, grantType: "authorization_code" });
			if (issued.kind === "refused") return { kind: "refused", refusal: issued };
			given.push(issued.access.token);
			expect((await s.redeem(code)).body).toEqual(refusedBody);
			return issued;
		},
	});
	expect(answer).toEqual(refusedOutcome);
	expect(await revoked(s, given[0] as string)).toBe(true);
});

it("uses a code up on a wrong verifier [rfc7636-4.6-b]", async () => {
	const s = await serve();
	const code = await s.issue();
	expect((await s.redeem(code, { code_verifier: "w".repeat(43) })).body.error).toBe(
		"invalid_grant",
	);
	expect((await s.redeem(code)).body).toEqual(refusedBody);
});

it("refuses a held challenge of another length, or of the same length with other bytes [rfc7636-4.5-a]", async () => {
	const s = await serve();
	const other = `${challenge.slice(0, -1)}${challenge.endsWith("A") ? "B" : "A"}`;
	for (const held of [challenge.slice(0, -1), `${challenge}A`, other]) {
		const code = await s.issue();
		await s.stores.records.change(nameOf(code), (kept) => ({
			value: overwritten(kept, { challenge: held }),
		}));
		expect((await s.redeem(code)).body, held).toEqual(refusedBody);
	}
});

it("adds an ID token when the code's scope holds the maker's scope, and names that scope [oidc-core-3.1.3.3-c] [oidc-core-3.1.3.2-f]", async () => {
	const s = await serve({ extra: [maker("openid")] });
	expect(s.app.get(codes).idTokenScope()).toBe("openid");
	expect((await s.redeem(await s.issue(["openid", "read"]))).body.id_token).toBe("id.token");
	expect((await s.redeem(await s.issue(["read"]))).body.id_token).toBeUndefined();
});

describe("what the ID token maker is told", () => {
	const recordingMaker = (asked: IdTokenRequest[]) =>
		defineModule({ name: "maker-recording", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(idTokens).by(() => ({
				scope: "openid",
				make: async (request) => {
					asked.push(request);
					return "id.token";
				},
			})),
		]);

	it("the acr the code was issued under, and none when it had none", async () => {
		const asked: IdTokenRequest[] = [];
		const s = await serve({ extra: [recordingMaker(asked)] });
		const facts = { ...s.facts, scope: ["openid"] };
		const issue = s.app.get(codes).issue;
		expect((await s.redeem(await issue({ ...facts, acr: "urn:x" }))).status).toBe(200);
		expect((await s.redeem(await issue(facts))).status).toBe(200);
		expect(asked.map((r) => r.acr)).toEqual(["urn:x", undefined]);
		expect("acr" in (asked[1] ?? {})).toBe(false);
	});

	it("the nonce and the authentication time the code was issued with", async () => {
		const asked: IdTokenRequest[] = [];
		const s = await serve({ extra: [recordingMaker(asked)] });
		const facts = { ...s.facts, scope: ["openid"], nonce: "n-1" };
		expect((await s.redeem(await s.app.get(codes).issue(facts))).status).toBe(200);
		const { authenticatedAt } = s.session.context;
		expect(asked).toMatchObject([{ nonce: "n-1", authenticatedAt }]);
	});

	it("that the authentication time is unknown, for a session whose login could not tell it", async () => {
		const asked: IdTokenRequest[] = [];
		const s = await serve({ extra: [recordingMaker(asked)] });
		const { session } = await s.app
			.get(sessions)
			.complete(testRequest(), { subject: "alice", amr: ["pwd"], authenticatedAt: "unknown" });
		const unknown = await s.app
			.get(codes)
			.issue({ ...s.facts, scope: ["openid"], session: session.id });
		expect((await s.redeem(unknown)).status).toBe(200);
		expect((await s.redeem(await s.issue(["openid"]))).status).toBe(200);
		expect(asked.map((r) => r.authenticatedAtUnknown)).toEqual([true, undefined]);
		expect("authenticatedAtUnknown" in (asked[1] ?? {})).toBe(false);
	});

	it("the session the code was issued in", async () => {
		const asked: IdTokenRequest[] = [];
		const s = await serve({ extra: [recordingMaker(asked)] });
		expect((await s.redeem(await s.issue(["openid"]))).status).toBe(200);
		expect(asked.map((r) => r.session)).toEqual([s.session.id]);
	});

	it("the redemption's name, the same the code's name gives", async () => {
		const asked: IdTokenRequest[] = [];
		const s = await serve({ extra: [recordingMaker(asked)] });
		const code = await s.issue(["openid"]);
		expect((await s.redeem(code)).status).toBe(200);
		expect(asked.map((r) => r.redemption)).toEqual([s.app.get(codes).redemptionOf(code)]);
	});

	it("the scope the code was issued for", async () => {
		const asked: IdTokenRequest[] = [];
		const s = await serve({ extra: [recordingMaker(asked)] });
		expect((await s.redeem(await s.issue(["openid", "read"]))).status).toBe(200);
		expect(asked.map((r) => r.scope)).toEqual([["openid", "read"]]);
	});
});

it("names no ID token scope without a maker", async () => {
	expect((await serve()).app.get(codes).idTokenScope()).toBeUndefined();
});

it("refuses to start with two ID token makers, without revocable tokens, without its tokens recorded to their session, or with an addition on a response field", async () => {
	const onAccessToken = defineModule(
		{ name: "adds-access_token", replicaSafe: true, takes: [] },
		(m) => [m.contribute(additions).by(() => ({ field: "access_token", issue: async () => "x" }))],
	);
	await expect(serve({ extra: [maker("openid"), maker("other")] })).rejects.toEqual(
		refusedFor("more than one ID token maker"),
	);
	await expect(serve({ revocation: "unsupported" })).rejects.toEqual(
		refusedFor("a configuration that cannot revoke access tokens cannot handle codes"),
	);
	// Composed by hand without session-tokens, a logout would leave the code's tokens alive.
	await expect(serve({ recorded: false })).rejects.toEqual(
		refusedFor("its tokens must be recorded to their session, so that a logout ends them"),
	);
	await expect(serve({ extra: [onAccessToken] })).rejects.toEqual(
		refusedFor("the response field access_token already exists"),
	);
});

it("lists a reused code until it is settled, and drops one that issued nothing once its record is gone", async () => {
	const s = await serve();
	const code = await s.issue();
	await s.redeem(code, { code_verifier: "w".repeat(43) });
	await s.redeem(code);
	expect(s.stores.pending()).toHaveLength(1);
	shift += 601_000;
	await afterSweep();
	expect(s.stores.pending()).toHaveLength(0);
});

it("never brings back a code that expired while it was being redeemed", async () => {
	const s = await serve();
	const code = await s.issue();
	const answer = await handleDirectly(s, code, {
		issue: async () => {
			shift += 601_000;
			const expiresAt = Date.now() + shift + 3_600_000;
			const access = { token: "t", id: "id", expiresAt, expiresIn: 3600, tokenType: "Bearer" };
			return { kind: "issued", access };
		},
	});
	expect(answer).toEqual(refusedOutcome);
	expect(s.stores.peek(nameOf(code))).toBeUndefined();
});

it("adds what a contribution issues alongside, under its own field, from the redeemed facts", async () => {
	const seen: Redeemed[] = [];
	const adding = (field: string, value: string | undefined) =>
		defineModule({ name: `adds-${field}`, replicaSafe: false, takes: [] }, (m) => [
			m.contribute(additions).by(() => ({
				field,
				issue: async (redeemed) => {
					seen.push(redeemed);
					return value;
				},
			})),
		]);
	const s = await serve({ extra: [adding("extra", "x"), adding("nothing", undefined)] });
	const { body } = await s.redeem(await s.issue());
	expect(body.extra).toBe("x");
	expect(body).not.toHaveProperty("nothing");
	expect(seen[0]).toMatchObject({
		subject: "alice",
		scope: ["read"],
		audience: ["https://api"],
		session: s.session.id,
		amr: ["pwd"],
	});
	expect(seen[0]?.client.id).toBe("app");
	expect(typeof seen[0]?.redemption).toBe("string");
	expect(seen[0]?.access).not.toHaveProperty("token");
	expect(typeof seen[0]?.access.id).toBe("string");
	expect(seen[0]).not.toHaveProperty("binding");
});

it("tells the additions the code's acr, and none for a code without one", async () => {
	const seen: Redeemed[] = [];
	const adding = defineModule({ name: "adds-acr", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(additions).by(() => ({
			field: "extra",
			issue: async (redeemed) => {
				seen.push(redeemed);
				return undefined;
			},
		})),
	]);
	const s = await serve({ extra: [adding] });
	await s.redeem(await s.app.get(codes).issue({ ...s.facts, acr: "urn:example:acr:high" }));
	await s.redeem(await s.issue());
	expect(seen.map((redeemed) => redeemed.acr)).toEqual(["urn:example:acr:high", undefined]);
	expect(seen[1]).not.toHaveProperty("acr");
});

it("tells the access token and the additions that a session did not know its authentication time", async () => {
	const seen: Redeemed[] = [];
	const adding = defineModule({ name: "adds-unknown", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(additions).by(() => ({
			field: "extra",
			issue: async (redeemed) => {
				seen.push(redeemed);
				return undefined;
			},
		})),
	]);
	const s = await serve({ extra: [adding] });
	const { session } = await s.app
		.get(sessions)
		.complete(testRequest(), { subject: "alice", amr: ["pwd"], authenticatedAt: "unknown" });
	const unknown = await s.redeem(await s.app.get(codes).issue({ ...s.facts, session: session.id }));
	const known = await s.redeem(await s.issue());
	const grantOf = async (body: Record<string, unknown>) => {
		const checked = await s.app.get(tokens).verifyAccess(String(body.access_token));
		return checked.kind === "valid" ? checked.grant : undefined;
	};
	// tokens writes no auth_time for it, so the token read back has no authentication time.
	expect(await grantOf(unknown.body)).not.toHaveProperty("authenticatedAt");
	expect(await grantOf(known.body)).toHaveProperty("authenticatedAt");
	expect(seen.map((redeemed) => redeemed.authenticatedAtUnknown)).toEqual([true, undefined]);
	expect(seen[1]).not.toHaveProperty("authenticatedAtUnknown");
});

it("takes back what was issued alongside a code that comes again", async () => {
	const issuedFor: string[] = [];
	const taken: string[] = [];
	const adding = defineModule({ name: "adds-taken", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(additions).by(() => ({
			field: "extra",
			issue: async (redeemed) => {
				issuedFor.push(redeemed.redemption);
				return "x";
			},
			revoke: async (redemption) => {
				taken.push(redemption);
			},
		})),
	]);
	const s = await serve({ extra: [adding] });
	const code = await s.issue();
	expect((await s.redeem(code)).status).toBe(200);
	expect(taken).toEqual([]);
	await s.redeem(code);
	expect(taken).toEqual(issuedFor);
});

it("tells an addition the binding the redeemed tokens carry", async () => {
	const seen: Redeemed[] = [];
	const adding = defineModule({ name: "adds-seen", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(additions).by(() => ({
			field: "extra",
			issue: async (redeemed) => {
				seen.push(redeemed);
				return undefined;
			},
		})),
	]);
	const s = await serve({ extra: [adding] });
	const binding = { member: "jkt", confirmation: "k1", tokenType: "DPoP" };
	const answer = await handleDirectly(s, await s.issue(), { binding });
	expect(answer?.kind).toBe("issued");
	expect(seen[0]?.binding).toEqual(binding);
});

it("refuses to issue a code for facts the session or the client contradict", async () => {
	const s = await serve();
	const issue = s.app.get(codes).issue;
	const bad = {
		"another subject": { subject: "mallory" },
		"scope outside the client": { scope: ["admin"] },
		"audience outside the client": { audience: ["https://other"] },
		"malformed challenge": { challenge: "short" },
		"unknown client": { clientId: "nobody" },
	};
	for (const [label, over] of Object.entries(bad)) {
		await expect(issue({ ...s.facts, ...over }), label).rejects.toThrow(TypeError);
	}
	// A session not entered at use may have closed meanwhile: the caller answers it as it can.
	await expect(issue({ ...s.facts, session: "x".repeat(43) }), "unknown session").rejects.toThrow(
		Unavailable,
	);
	expect(typeof (await issue(s.facts))).toBe("string");
});

it("marks nothing void when listing a reused code fails, so a later reuse still revokes [rfc6749-4.1.2-e]", async () => {
	const s = await serve();
	const code = await s.issue();
	const first = await s.redeem(code);
	s.stores.voids.failNext("add");
	expect((await s.redeem(code)).status).not.toBe(200);
	const kept = s.stores.peek(nameOf(code));
	const read = kept && fromStored(kept);
	expect(read).toBeDefined();
	expect(read).not.toHaveProperty("void");
	expect((await s.redeem(code)).body).toEqual(refusedBody);
	expect(await revoked(s, String(first.body.access_token))).toBe(true);
});

/** Notes each redemption in a session as told, running `during` first when given. */
const noting = (noted: [string, string][], during?: () => Promise<void>) =>
	defineModule({ name: "noting", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(sessionRedemptions).by(() => ({
			name: "noting",
			redeemed: async (session, clientId) => {
				await during?.();
				noted.push([session, clientId]);
			},
		})),
	]);

it("tells each contribution the session and client a code was redeemed in", async () => {
	const noted: [string, string][] = [];
	const s = await serve({ extra: [noting(noted)] });
	expect((await s.redeem(await s.issue())).status).toBe(200);
	expect(noted).toEqual([[s.session.id, "app"]]);
});

it("tells how long a code lives, as code-lifetime says", async () => {
	expect((await serve()).app.get(codes).lifetimeMs()).toBe(600_000);
	await stop();
	const short = await serve({ codeGrant: { "code-lifetime": "30s", "sweep-interval": "1s" } });
	expect(short.app.get(codes).lifetimeMs()).toBe(30_000);
});

it("names a code's redemption as its record is named, from the code alone", async () => {
	const s = await serve();
	const code = await s.issue();
	expect(s.app.get(codes).redemptionOf(code)).toBe(nameOf(code));
	expect(s.app.get(codes).redemptionOf(code)).not.toBe(code);
});

describe("redemption hooks", () => {
	/** Notes what each hook is told, in order, into `seen`; `fail` makes one throw. */
	const hooking = (
		seen: string[],
		fail: { pin?: boolean; redeemed?: boolean } = {},
		redeemedSeen: Redeemed[] = [],
	) =>
		defineModule({ name: "hooking", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(redemptionHooks).by(() => ({
				name: "hooking",
				pin: async (redemption) => {
					seen.push(`pin ${redemption}`);
					if (fail.pin) throw new Error("cannot pin");
				},
				redeemed: async (redeemed) => {
					seen.push(`redeemed ${redeemed.redemption}`);
					redeemedSeen.push(redeemed);
					if (fail.redeemed) throw new Error("cannot note");
				},
			})),
			m.contribute(additions).by(() => ({
				field: "extra",
				issue: async (redeemed) => {
					seen.push(`addition ${redeemed.redemption}`);
					return undefined;
				},
				revoke: async (redemption) => {
					seen.push(`revoke ${redemption}`);
				},
			})),
		]);

	it("pins a used-up code before its token is issued, and tells of the redemption after the additions", async () => {
		const seen: string[] = [];
		const redeemedSeen: Redeemed[] = [];
		const s = await serve({ extra: [hooking(seen, {}, redeemedSeen)] });
		const code = await s.issue();
		const name = nameOf(code);
		const answer = await handleDirectly(s, code, {
			issue: async (g) => {
				seen.push("issue");
				const issued = await s.app.get(tokens).issue({ grant: g, grantType: "authorization_code" });
				return issued.kind === "refused" ? { kind: "refused", refusal: issued } : issued;
			},
		});
		expect(answer).toMatchObject({ kind: "issued" });
		expect(seen).toEqual([`pin ${name}`, "issue", `addition ${name}`, `redeemed ${name}`]);
		expect(redeemedSeen).toMatchObject([{ redemption: name, subject: "alice", scope: ["read"] }]);
		expect(redeemedSeen[0]?.access.id).toEqual(expect.any(String));
	});

	it("pins nothing for a code refused before it is used up, or used up by a wrong verifier", async () => {
		const seen: string[] = [];
		const s = await serve({ extra: [hooking(seen)] });
		const code = await s.issue();
		expect((await s.redeem(code, { redirect_uri: "https://other.example/cb" })).status).toBe(400);
		expect((await s.redeem(code)).status).toBe(400);
		const other = await s.issue();
		expect((await s.redeem(other, { code_verifier: "w".repeat(43) })).status).toBe(400);
		expect(seen.filter((step) => step.startsWith("pin"))).toEqual([]);
	});

	it("voids the code and issues nothing when the pin fails", async () => {
		const seen: string[] = [];
		const s = await serve({ extra: [hooking(seen, { pin: true })] });
		const code = await s.issue();
		const answer = await handleDirectly(s, code, {
			issue: async () => {
				throw new Error("issued after a failed pin");
			},
		}).catch((error: unknown) => ({ kind: "thrown", error }));
		expect(answer).toMatchObject({ kind: "thrown", error: { message: "cannot pin" } });
		expect(keptOf(s, code)).toMatchObject({ state: "consumed", void: true });
		expect(keptOf(s, code)).not.toHaveProperty("token");
	});

	it("voids the code, revoking its token and what the additions gave, when telling of the redemption fails", async () => {
		const seen: string[] = [];
		const s = await serve({ extra: [hooking(seen, { redeemed: true })] });
		const code = await s.issue();
		const given: string[] = [];
		const answer = await handleDirectly(s, code, {
			issue: async (g) => {
				const issued = await s.app.get(tokens).issue({ grant: g, grantType: "authorization_code" });
				if (issued.kind === "refused") return { kind: "refused", refusal: issued };
				given.push(issued.access.token);
				return issued;
			},
		}).catch((error: unknown) => ({ kind: "thrown", error }));
		expect(answer).toMatchObject({ kind: "thrown", error: { message: "cannot note" } });
		expect(await revoked(s, given[0] ?? "")).toBe(true);
		expect(seen).toContain(`revoke ${nameOf(code)}`);
	});
});

describe("tokens issued while the exchange goes wrong are revoked", () => {
	const redeemWith = async (
		s: Served,
		options: { during?: (issued: IssuedAccess) => Promise<void>; scope?: readonly string[] } = {},
	) => {
		const given: string[] = [];
		const answer = await handleDirectly(s, await s.issue(options.scope), {
			issue: async (g) => {
				const issued = await s.app.get(tokens).issue({ grant: g, grantType: "authorization_code" });
				if (issued.kind === "refused") return { kind: "refused", refusal: issued };
				given.push(issued.access.token);
				await options.during?.(issued.access);
				return issued;
			},
		}).catch((error: unknown) => ({ kind: "thrown", error }));
		expect(given, "one token issued").toHaveLength(1);
		return { answer, token: given[0] as string };
	};
	const failingAddition = (issue: () => Promise<string | undefined>) =>
		defineModule({ name: "failing-addition", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(additions).by(() => ({ field: "extra", issue })),
		]);
	const failingMaker = (make: () => Promise<string>) =>
		defineModule({ name: "failing-maker", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(idTokens).by(() => ({ scope: "openid", make })),
		]);

	it("when the session closes between issuing and the second check", async () => {
		const s = await serve();
		const { answer, token } = await redeemWith(s, {
			during: async () => {
				await s.app.get(sessions).close(s.session.id);
			},
		});
		expect(answer).toEqual(refusedOutcome);
		expect(await revoked(s, token)).toBe(true);
	});

	it("when recording it to the session fails in issuing, leaving the code used up", async () => {
		const told: string[] = [];
		const failing = defineModule({ name: "failing-record", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(sessionIssuances).by(() => ({
				issued: async (_, { id }) => {
					told.push(`stand-in.${id}`);
					throw new Unavailable("test");
				},
			})),
		]);
		const s = await serve({ extra: [failing] });
		const code = await s.issue();
		expect((await s.redeem(code)).status).toBe(503);
		expect(told).toHaveLength(1);
		expect(await revoked(s, told[0] ?? "")).toBe(true);
		expect(keptOf(s, code)).toMatchObject({ state: "consumed" });
		expect(keptOf(s, code)).not.toHaveProperty("token");
	});

	it("when a redemption cannot be noted for the session", async () => {
		const s = await serve({
			extra: [
				noting([], async () => {
					throw new Error("cannot note");
				}),
			],
		});
		const { answer, token } = await redeemWith(s);
		expect(answer).toMatchObject({ kind: "thrown" });
		expect(await revoked(s, token)).toBe(true);
	});

	it("when the session closes while the redemption is noted", async () => {
		const noted: [string, string][] = [];
		let s: Served | undefined;
		const close = async () => {
			await s?.app.get(sessions).close(s.session.id);
		};
		s = await serve({ extra: [noting(noted, close)] });
		const { answer, token } = await redeemWith(s);
		expect(answer).toEqual(refusedOutcome);
		expect(noted).toHaveLength(1);
		expect(await revoked(s, token)).toBe(true);
	});

	it("when the session falls short of a requirement while the redemption is noted", async () => {
		const short = { now: false };
		const s = await serve({
			extra: [
				shortToUse(short),
				noting([], async () => {
					short.now = true;
				}),
			],
		});
		const { answer, token } = await redeemWith(s);
		expect(answer).toEqual(refusedOutcome);
		expect(await revoked(s, token)).toBe(true);
	});

	it("when an addition or the ID token fails, before or after it gives a promise", async () => {
		const cases: Record<string, [Module, readonly string[] | undefined]> = {
			"addition rejects": [
				failingAddition(async () => {
					throw new Error("cannot issue");
				}),
				undefined,
			],
			"addition throws": [
				failingAddition(() => {
					throw new Error("cannot issue");
				}),
				undefined,
			],
			"maker rejects": [
				failingMaker(async () => {
					throw new Error("cannot sign");
				}),
				["openid", "read"],
			],
			"maker throws": [
				failingMaker(() => {
					throw new Error("cannot sign");
				}),
				["openid", "read"],
			],
		};
		for (const [name, [failing, scope]] of Object.entries(cases)) {
			const s = await serve({ extra: [failing] });
			const { answer, token } = await redeemWith(s, scope ? { scope } : {});
			expect(answer, name).toMatchObject({ kind: "thrown" });
			expect(await revoked(s, token), name).toBe(true);
			await stop();
		}
	});
});

// Of the credentials the guessing items list, the provider makes the codes and tokens alone: users choose passwords, operators register client secrets.
// Session, consent and CSRF handles are no OAuth credentials, so they lie outside these items.
it("makes each code of 32 fresh random bytes, nothing of its challenge, and gives the challenge out nowhere [rfc6749-10.10-a] [rfc6749-10.10-b] [rfc6749-10.10-c] [rfc7636-4.4-b]", async () => {
	const s = await serve();
	const code = await s.issue();
	const made = drawn.at(-1);
	expect(made && Buffer.from(made).toString("base64url")).toBe(code);
	const other = await s.issue();
	expect(other).not.toBe(code);
	expect(Buffer.from(drawn.at(-1) ?? []).toString("base64url")).toBe(other);
	expect(code).not.toContain(challenge);
	const redeemed = await s.redeem(code);
	expect(redeemed.status).toBe(200);
	expect(JSON.stringify(redeemed.body)).not.toContain(challenge);
});

it("offers the shape of an S256 challenge: 43 base64url characters, as RFC 7636 makes it", async () => {
	const { challengeShape } = await import("../src/contract.ts");
	expect(challengeShape.test("A".repeat(43))).toBe(true);
	expect(challengeShape.test(`${"a".repeat(42)}_`)).toBe(true);
	for (const refused of [
		"A".repeat(42),
		"A".repeat(44),
		`${"A".repeat(42)}+`,
		`${"A".repeat(42)}=`,
	]) {
		expect(challengeShape.test(refused), refused).toBe(false);
	}
});

it("takes all its module names, with an ID token maker and an addition or with neither", async () => {
	const adding = defineModule({ name: "adds-extra", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(additions).by(() => ({ field: "extra", issue: async () => undefined })),
	]);
	const hooked = defineModule({ name: "hooked", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(redemptionHooks).by(() => ({
			name: "hooked",
			pin: async () => {},
			redeemed: async () => {},
		})),
	]);
	for (const extra of [[], [maker("openid"), adding, hooked]]) {
		const { input } = assembly({ extra });
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect((await takesUnused(input))["code-grant"]).toBeUndefined();
	}
});
