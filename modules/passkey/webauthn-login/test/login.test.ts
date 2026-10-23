import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Passkeys, passkeys } from "@mod/passkeys";
import rateLimitModule from "@mod/rate-limit/module";
import { type Beginning, lineage } from "@mod/refresh";
import secretHashModule from "@mod/secret-hash/module";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocation } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import { type IssuanceRequest, issuancePolicies, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { afterEach, describe, expect, it } from "vitest";
import { passkeyAmr, webauthnGrantType } from "../src/contract.ts";
import { type LoginParts, passkeyGrant } from "../src/grant/grant.ts";
import login from "../src/module.ts";
import { section as loginSection } from "../src/section.ts";

const origin = "https://as.example";
const start = 1_800_000_000_000;
let now = start;
const runtime = quietRuntime({ clock: { now: () => now } });
let stop = async () => {};
afterEach(async () => {
	await stop();
	now = start;
});

type Asserted = Awaited<ReturnType<Passkeys["assert"]>>;
const asserted = (challengedAt: number, userVerified = true, backupEligible = false): Asserted => ({
	kind: "asserted",
	subject: "alice",
	challengedAt,
	userVerified,
	backupEligible,
});
const options = { challenge: "c".repeat(43), rpId: "rp.example", userVerification: "preferred" };

type Refusal = Extract<Asserted, { kind: "refused" }>["reason"];
/** Every refusal of `passkeys`, with the kind the audit records; the type refuses a list that leaves one out. */
const recordedAs = {
	malformed: "assertion_malformed",
	challenge: "challenge_invalid",
	origin: "origin_not_allowed",
	"top-origin": "top_origin_not_allowed",
	rp: "rp_mismatch",
	algorithm: "algorithm_not_allowed",
	signature: "signature_invalid",
	"sign-count": "sign_count_not_increased",
	"user-handle": "user_handle_mismatch",
	"user-verification": "user_verification_missing",
	"backup-eligibility": "backup_eligibility_changed",
	"unknown-credential": "credential_unknown",
	"no-user-handle": "user_handle_missing",
	raced: "sign_count_raced",
} satisfies Record<Refusal, string>;

async function serve(section: Record<string, unknown> = {}, extra: Module[] = []) {
	const seen: unknown[] = [];
	const requesters: { asked: string[]; redeemed: string[] } = {
		asked: [],
		redeemed: [],
	};
	const begun: Beginning[] = [];
	const recorded = auditStandIn();
	const state = {
		answer: asserted(now - 5000),
		down: false,
		family: "fam.secret" as string | undefined,
	};
	const standIns = defineModule({ name: "stand-ins" }, (m) => [
		m.provide(passkeys).by(() => ({
			challenge: async (requester) => {
				requesters.asked.push(requester);
				if (state.down) throw new Unavailable("passkeys");
				return { options };
			},
			assert: async (response, requester) => {
				seen.push(response);
				requesters.redeemed.push(requester);
				if (state.down) throw new Unavailable("passkeys");
				return state.answer;
			},
		})),
		m.provide(lineage).by(() => ({
			of: async () => ({ kind: "none" }),
			adopt: async () => "ended",
			start: async (beginning) => {
				begun.push(beginning);
				return state.family;
			},
		})),
	]);
	const allowed = (grants: string[]) =>
		allowancesFor({ grants, scopes: ["read", "write"], "default-scopes": ["read"] });
	const app = await assemble({
		modules: [
			http,
			clientsModule,
			secretHashModule,
			issuerModule,
			tokensStandIn(),
			grantCaller,
			clientAllowanceModule,
			subjectRevocationStandIn,
			rateLimitModule,
			recorded.module,
			simulatedStore().module,
			standIns,
			login,
			...extra,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": origin }),
			...issuerConfig({ url: origin }),
			...clientsConfig([
				confidentialClient({ id: "app", sections: allowed([webauthnGrantType]) }),
				publicClient({ id: "pub", sections: allowed([webauthnGrantType]) }),
				confidentialClient({
					id: "bare",
					sections: allowancesFor({
						grants: [webauthnGrantType],
						scopes: ["read"],
						"default-scopes": [],
					}),
				}),
			]),
			"webauthn-login": section,
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const call = (params: Record<string, unknown>, as = "app", confirmation?: string) =>
		app
			.get(grantCalls)
			.call(
				webauthnGrantType,
				as,
				{ grant_type: webauthnGrantType, ...params },
				confirmation ? { binding: { member: "jkt", confirmation, tokenType: "DPoP" } } : {},
			);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	const ask = (init: RequestInit = asApp) =>
		fetch(`${base}/oauth/webauthn/authentication/options`, { method: "POST", ...init });
	return { app, state, seen, requesters, begun, events: recorded.events, call, ask };
}

const assertion = { id: "cred", response: { userHandle: "h" } };
const asApp = { headers: { "content-type": "application/json" }, body: '{"client_id":"app"}' };

describe("the passkey grant", () => {
	it("issues the client's access token for an asserted passkey, with amr pop and the challenge's time, and starts its family with the same", async () => {
		const s = await serve();
		const outcome = await s.call({ assertion, scope: "read write" });
		expect(outcome).toEqual({
			kind: "issued",
			body: {
				access_token: expect.any(String),
				token_type: "Bearer",
				expires_in: expect.any(Number),
				refresh_token: "fam.secret",
				scope: "read write",
			},
		});
		expect(s.seen).toEqual([assertion]);
		expect(s.requesters.redeemed).toEqual(["app"]);
		if (outcome.kind !== "issued") expect.unreachable("the passkey is asserted");
		const check = await s.app.get(tokens).verifyAccess(String(outcome.body.access_token));
		if (check.kind !== "valid") expect.unreachable("the access token verifies");
		expect(check.grant).toMatchObject({
			subject: "alice",
			issuedTo: "app",
			audience: [origin],
			scope: ["read", "write"],
			amr: ["pop"],
			authenticatedAt: now - 5000,
		});
		const family = { scope: ["read", "write"], audience: [origin], authenticatedAt: now - 5000 };
		expect(s.begun).toMatchObject([{ subject: "alice", amr: ["pop"], ...family }]);
		expect(s.begun[0]?.client.id).toBe("app");
		const expiresAt = now + Number(outcome.body.expires_in) * 1000;
		expect(s.begun[0]?.access).toEqual({ id: check.id, expiresAt });
	});

	it("gives amr pop alone, whether or not the user was verified or the passkey is backup eligible", async () => {
		expect(passkeyAmr).toEqual(["pop"]);
		const s = await serve();
		for (const [userVerified, backupEligible] of [
			[true, false],
			[false, false],
			[true, true],
		]) {
			s.state.answer = asserted(now - 5000, userVerified, backupEligible);
			const outcome = await s.call({ assertion });
			const body = outcome.kind === "issued" ? outcome.body : {};
			const check = await s.app.get(tokens).verifyAccess(String(body.access_token));
			const label = `${userVerified} ${backupEligible}`;
			expect(check.kind === "valid" && check.grant.amr, label).toEqual(["pop"]);
			expect(s.begun.at(-1)?.amr, label).toEqual(["pop"]);
		}
	});

	it("takes a JSON body only", () => {
		expect(webauthnGrantType).toBe("urn:o3co:oauth:grant-type:webauthn");
		expect(passkeyGrant({} as LoginParts).bodies).toEqual(["json"]);
	});

	it("answers no scope member when it issues no scope", async () => {
		const s = await serve();
		const outcome = await s.call({ assertion }, "bare");
		expect(outcome.kind === "issued" && "scope" in outcome.body).toBe(false);
	});

	it("answers no refresh token when the family does not start", async () => {
		const s = await serve();
		s.state.family = undefined;
		const outcome = await s.call({ assertion });
		expect(outcome.kind === "issued" && outcome.body).toMatchObject({ scope: "read" });
		expect(outcome.kind === "issued" && "refresh_token" in outcome.body).toBe(false);
	});

	it("binds the access token and the family to the request's binding", async () => {
		const s = await serve();
		const outcome = await s.call({ assertion }, "pub", "thumb");
		expect(outcome.kind === "issued" && outcome.body.token_type).toBe("DPoP");
		expect(s.begun[0]?.binding).toEqual({
			member: "jkt",
			confirmation: "thumb",
			tokenType: "DPoP",
		});
	});

	it("answers every refusal of the passkeys and the revocation alike, recording only the kind", async () => {
		const s = await serve();
		const refusal = (reason: string) => ({
			kind: "passkey.login.refused",
			attributes: { client: "app", reason },
			at: now,
		});
		const answers = new Set<string>();
		for (const [reason, kind] of Object.entries(recordedAs) as [Refusal, string][]) {
			s.state.answer = { kind: "refused", reason };
			answers.add(JSON.stringify(await s.call({ assertion })));
			expect(s.events.at(-1), reason).toEqual(refusal(kind));
		}
		await s.app.get(subjectRevocation).revoke("alice");
		s.state.answer = asserted(now - 5000);
		answers.add(JSON.stringify(await s.call({ assertion })));
		expect(s.events.at(-1)).toEqual(refusal("authentication_revoked"));
		expect([...answers].map((answer) => JSON.parse(answer))).toEqual([
			{ kind: "error", error: "invalid_grant", description: "passkey assertion not accepted" },
		]);
		expect(s.events).toHaveLength(Object.keys(recordedAs).length + 1);
		expect(s.begun).toEqual([]);
	});

	it("issues through the issuance policies without a session, starting no family when they refuse", async () => {
		const asked: IssuanceRequest[] = [];
		const refusing = defineModule({ name: "refusing" }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async (request) => {
					asked.push(request);
					return { kind: "refused", reason: "test_reason", description: "refused here" };
				},
			})),
		]);
		const s = await serve({}, [refusing]);
		const outcome = await s.call({ assertion });
		expect(outcome).toEqual({ kind: "error", error: "invalid_grant", description: "refused here" });
		expect(asked.map(({ grantType, session }) => [grantType, session])).toEqual([
			[webauthnGrantType, undefined],
		]);
		expect(s.begun).toEqual([]);
	});

	it("refuses a challenge made far ahead of the clock as invalid_grant, starting no family", async () => {
		const s = await serve();
		s.state.answer = asserted(now + 300_001);
		expect(await s.call({ assertion })).toMatchObject({ kind: "error", error: "invalid_grant" });
		expect(s.begun).toEqual([]);
	});

	it("asks for an assertion, and refuses one that is no object before the passkeys see it", async () => {
		const s = await serve();
		expect(await s.call({})).toMatchObject({ kind: "error", error: "invalid_request" });
		for (const sent of ["text", ["a"], null, 7]) {
			expect(await s.call({ assertion: sent })).toMatchObject({
				kind: "error",
				error: "invalid_grant",
			});
		}
		expect(s.seen).toEqual([]);
	});

	it("refuses a scope beyond the client's allowance with invalid_scope, after the passkeys judged the assertion", async () => {
		const s = await serve();
		expect(await s.call({ assertion, scope: "admin" })).toMatchObject({
			kind: "error",
			error: "invalid_scope",
		});
		expect(s.seen).toEqual([assertion]);
		expect(s.begun).toEqual([]);
	});

	it("refuses a subject revoked after the challenge was made", async () => {
		const s = await serve();
		await s.app.get(subjectRevocation).revoke("alice");
		expect(await s.call({ assertion })).toMatchObject({ kind: "error", error: "invalid_grant" });
	});

	it("answers a scope beyond the allowance before the revocation boundary", async () => {
		const s = await serve();
		await s.app.get(subjectRevocation).revoke("alice");
		expect(await s.call({ assertion, scope: "admin" })).toMatchObject({ error: "invalid_scope" });
		expect(s.events).toEqual([]);
	});

	it("issues for a challenge made after the revocation", async () => {
		const s = await serve();
		await s.app.get(subjectRevocation).revoke("alice");
		// A challenge made 2 s after the revocation, answered 1 s later.
		s.state.answer = asserted(now + 2000);
		now += 3000;
		expect((await s.call({ assertion })).kind).toBe("issued");
	});

	it("is unavailable when the passkeys cannot tell, never a refusal", async () => {
		const s = await serve();
		s.state.down = true;
		await expect(s.call({ assertion })).rejects.toSatisfy(isUnavailable);
	});
});

describe("the authentication options route", () => {
	it("answers the same options whatever else the body holds", async () => {
		const s = await serve();
		const json = (value: unknown) => ({
			headers: { "content-type": "application/json" },
			body: JSON.stringify(value),
		});
		const sent = {
			"a JSON username": json({ client_id: "app", username: "alice" }),
			"a large JSON body": json({ client_id: "app", userId: "alice", padding: "x".repeat(60_000) }),
			"a form": {
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: "username=bob&client_id=app",
			},
		};
		for (const [name, init] of Object.entries(sent)) {
			const answer = await s.ask(init);
			expect(answer.status, name).toBe(200);
			expect(answer.headers.get("cache-control"), name).toBe("no-store");
			expect(await answer.json(), name).toEqual(options);
		}
	});

	it("makes the challenge for the client_id the request names", async () => {
		const s = await serve();
		const form = { "content-type": "application/x-www-form-urlencoded" };
		expect((await s.ask()).status).toBe(200);
		expect((await s.ask({ headers: form, body: "client_id=pub" })).status).toBe(200);
		expect(s.requesters.asked).toEqual(["app", "pub"]);
	});

	it("refuses a missing client_id, and one that is not one non-empty string, making no challenge", async () => {
		const s = await serve();
		const json = (value: unknown) => ({
			headers: { "content-type": "application/json" },
			body: JSON.stringify(value),
		});
		const sent = {
			"no body": {},
			"no client_id": json({ username: "alice" }),
			"a form without one": {
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: "username=bob",
			},
			"a number": json({ client_id: 7 }),
			"a list": json({ client_id: ["app"] }),
			empty: json({ client_id: "" }),
			repeated: {
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: "client_id=app&client_id=pub",
			},
		};
		for (const [name, init] of Object.entries(sent)) {
			const answer = await s.ask(init);
			expect([answer.status, await answer.json()], name).toEqual([
				400,
				{ error: "invalid_request" },
			]);
			expect(answer.headers.get("cache-control"), name).toBe("no-store");
		}
		expect(s.requesters.asked).toEqual([]);
	});

	it("limits requests per source, then answers 429", async () => {
		const s = await serve({ requests: 2, window: "1m" });
		expect((await s.ask()).status).toBe(200);
		expect((await s.ask()).status).toBe(200);
		expect((await s.ask()).status).toBe(429);
	});

	it("counts requests over the window", async () => {
		const s = await serve({ requests: 1, window: "1m" });
		expect((await s.ask()).status).toBe(200);
		now += 59_000;
		expect((await s.ask()).status).toBe(429);
		now += 1_000;
		expect((await s.ask()).status).toBe(200);
	});

	it("answers 503 when the challenge cannot be kept", async () => {
		const s = await serve();
		s.state.down = true;
		expect((await s.ask()).status).toBe(503);
	});
});

describe("the operator section", () => {
	const takes = (value: Record<string, unknown>) => loginSection.safeParse(value).success;

	it("defaults to 60 requests in a window of 1m, read in seconds", () => {
		expect(loginSection.parse({})).toEqual({ requests: 60, window: 60 });
	});

	it("reads the window as an operator writes it, with a unit, from 1s to 1d", () => {
		expect(loginSection.parse({ window: "30m" })).toEqual({ requests: 60, window: 1800 });
		const bounds = ["0s", "1s", "1d", "86401s"].map((window) => takes({ window }));
		expect(bounds).toEqual([false, true, true, false]);
		expect(takes({ window: "1500ms" })).toBe(false);
	});

	it("refuses to start with a window that names no unit, a number or digits alone", async () => {
		const unitless = [
			[60, "written with its unit, such as 30s"],
			["60", "duration must name its unit"],
		] as const;
		for (const [written, reason] of unitless) {
			await expect(serve({ window: written }), String(written)).rejects.toMatchObject({
				refusals: [{ where: "webauthn-login.window", reason }],
			});
		}
		expect(loginSection.safeParse({ window: "60" }).error?.issues).toMatchObject([
			{ path: ["window"], params: { problem: "missing-unit" } },
		]);
	});

	it("refuses to start with window-seconds, a name it no longer reads", async () => {
		await expect(serve({ "window-seconds": 60 })).rejects.toMatchObject({
			refusals: [{ where: "webauthn-login" }],
		});
		expect(takes({ "window-seconds": 60 })).toBe(false);
	});

	it("takes whole numbers of requests within bounds, and no other key", () => {
		expect([takes({ requests: 1 }), takes({ requests: 100_000 })]).toEqual([true, true]);
		const refused = {
			"no requests": { requests: 0 },
			"too many requests": { requests: 100_001 },
			"a fraction of requests": { requests: 1.5 },
			"an unknown key": { limit: 1 },
		};
		for (const [name, value] of Object.entries(refused)) expect(takes(value), name).toBe(false);
	});
});
