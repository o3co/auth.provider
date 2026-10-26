import { generateKeyPairSync } from "node:crypto";
import { areaTarget, auditEvents, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { federationScene } from "../src/main.ts";
import { type Browser, browser as openBrowser, probeClient } from "./browser.ts";
import { fakeUpstream } from "./upstream.ts";

const origin = "https://issuer.example";
const landing = "https://app.example/home";
const start = "/session/oauth/federation/corp";
const pair = generateKeyPairSync("ed25519");
const client = { id: "as-client", secret: "as-client-secret-0123456789" };

let upstream: Awaited<ReturnType<typeof fakeUpstream>>;
let running: Started;
let base = "";
beforeAll(async () => {
	upstream = await fakeUpstream(client);
	const scene = federationScene({
		origin,
		keys: {
			signing: {
				kid: "fed",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		idps: [
			{ name: "corp", issuer: upstream.issuer, clientId: client.id, clientSecret: client.secret },
		],
		landing,
		returnTargets: ["https://app.example/back"],
		users: [
			{
				identifier: "alice",
				password: "correct horse battery",
				upstream: { idp: "corp", subject: "u-alice" },
			},
		],
		clients: [probeClient],
	});
	running = await areaTarget().start(scene);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
	await upstream?.stop();
});

const browser = () => openBrowser(() => base, origin);

/** Starts a login and authorizes it upstream as `subject`, answering the callback query. */
async function authorized(b: Browser, subject: string, forged = false) {
	const started = await b.get(start);
	expect(started.status).toBe(302);
	expect(started.location.startsWith(`${upstream.issuer}/authorize?`)).toBe(true);
	return upstream.authorize(started.location, { subject, forged });
}

describe("federation", () => {
	it("logs a browser in through its upstream, landing where the operator says", async () => {
		const b = browser();
		const query = await authorized(b, "u-alice");
		const back = await b.get(`${start}/callback?${query}`);
		expect([back.status, back.location]).toEqual([302, landing]);
		expect(await b.session()).toBe(true);
	});

	it("refuses an id_token the upstream did not sign [oidc-core-3.1.3.7-i] [oidc-core-3.1.3.7-j] [oidc-core-16.3-a]", async () => {
		const b = browser();
		const query = await authorized(b, "u-alice", true);
		const back = await b.get(`${start}/callback?${query}`);
		expect(back.status).toBe(502);
		expect(await b.session()).toBe(false);
	});

	it("refuses an answer naming another issuer before its code is used [rfc9700-4.4.2.1-a] [rfc9700-2.1-e] [rfc9700-2.1-f]", async () => {
		const b = browser();
		const query = await authorized(b, "u-alice");
		const code = query.get("code") ?? "";
		query.set("iss", "http://127.0.0.1:9/");
		const back = await b.get(`${start}/callback?${query}`);
		expect(back.status).toBe(502);
		expect(upstream.tokenCalls).not.toContain(code);
		expect(await b.session()).toBe(false);
	});

	it("refuses an upstream identity linked to no one", async () => {
		const b = browser();
		const query = await authorized(b, "u-nobody");
		const back = await b.get(`${start}/callback?${query}`);
		expect(back.status).toBe(401);
		expect(await b.session()).toBe(false);
	});

	it("spends a transaction only with its own state, and only once [oidc-core-3.1.2.7-a] [oidc-core-3.1.3.7-l] [rfc9700-4.2.4-b]", async () => {
		const b = browser();
		const query = await authorized(b, "u-alice");
		const wrong = new URLSearchParams(query);
		wrong.set("state", "not-the-state");
		expect((await b.get(`${start}/callback?${wrong}`)).status).toBe(400);
		// Kept from before the callback that takes it, so a reuse carries the transaction still.
		const kept = b.cookies();
		expect((await b.get(`${start}/callback?${query}`)).status).toBe(302);
		expect((await b.get(`${start}/callback?${query}`, kept)).status).toBe(400);
	});

	it("refuses a callback that carries no transaction [oidc-core-3.1.2.7-a] [rfc9700-2.1-d]", async () => {
		const b = browser();
		const query = await authorized(b, "u-alice");
		const stranger = browser();
		expect((await stranger.get(`${start}/callback?${query}`)).status).toBe(400);
		expect(await stranger.session()).toBe(false);
	});

	it("answers an upstream's refusal with 400 [oidc-core-3.1.2.7-a]", async () => {
		const b = browser();
		const query = await authorized(b, "u-alice");
		const refused = new URLSearchParams({
			error: "access_denied",
			state: query.get("state") ?? "",
			iss: upstream.issuer,
		});
		expect((await b.get(`${start}/callback?${refused}`)).status).toBe(400);
		expect(await b.session()).toBe(false);
	});

	it("refuses a start that would return anywhere but a listed target [rfc9700-4.1.3-b] [rfc9700-2.1-b]", async () => {
		const b = browser();
		const elsewhere = encodeURIComponent("https://evil.example/");
		expect((await b.get(`${start}?redirect_to=${elsewhere}`)).status).toBe(400);
		const listed = encodeURIComponent("https://app.example/back");
		expect((await b.get(`${start}?redirect_to=${listed}`)).status).toBe(302);
	});
});

describe.runIf(areaTarget().can(auditEvents.need))("federation: audit events", () => {
	it("records a login with its subject, and logins that failed with their reasons", async () => {
		const trail = auditEvents.of(running);
		const login = async (subject: string, forged = false) => {
			const b = browser();
			const query = await authorized(b, subject, forged);
			const { events } = await trail.during(() => b.get(`${start}/callback?${query}`));
			return { events, on: { idp: "corp", source: b.from } };
		};
		const ok = await login("u-alice");
		expect(ok.events).toEqual([
			{
				kind: "federation.login.succeeded",
				at: expect.any(Number),
				subject: expect.stringMatching(/./),
				attributes: ok.on,
			},
		]);
		for (const [subject, forged, reason] of [
			["u-nobody", false, "unknown_user"],
			["u-alice", true, "exchange_failed"],
		] as const) {
			const failed = await login(subject, forged);
			expect(failed.events).toEqual([
				{
					kind: "federation.login.failed",
					at: expect.any(Number),
					attributes: { ...failed.on, reason },
				},
			]);
			expect(JSON.stringify(failed.events)).not.toMatch(/u-alice|u-nobody/);
		}
		expect(JSON.stringify(ok.events)).not.toContain("u-alice");
	});

	it("records an upstream's refusal, and nothing for a callback that carries no transaction", async () => {
		const trail = auditEvents.of(running);
		const b = browser();
		const query = await authorized(b, "u-alice");
		const stranger = await trail.during(() => browser().get(`${start}/callback?${query}`));
		expect([stranger.result.status, stranger.events]).toEqual([400, []]);
		const refused = new URLSearchParams({
			error: "access_denied",
			state: query.get("state") ?? "",
			iss: upstream.issuer,
		});
		const { events } = await trail.during(() => b.get(`${start}/callback?${refused}`));
		expect(events).toEqual([
			{
				kind: "federation.login.failed",
				at: expect.any(Number),
				attributes: { idp: "corp", source: b.from, reason: "upstream_refused" },
			},
		]);
	});
});
