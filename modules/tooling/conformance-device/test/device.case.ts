import { generateKeyPairSync } from "node:crypto";
import { areaTarget, auditEvents, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { deviceScene } from "../src/main.ts";

const issuer = "https://issuer.example";
/** Unlike either system's default, so the limit is seen to come from the scene. */
const attempts = 8;
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code";
const pair = generateKeyPairSync("ed25519");
const client = (id: string, grants: string[]): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: `${id}-secret-0123456789abcdef`,
	grants,
	scopes: ["read"],
	defaultScopes: ["read"],
});
const scene = deviceScene({
	issuer,
	keys: {
		signing: {
			kid: "dv",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	// svc is allowed no grant, so not the device grant, and the scene needs no other grant composed.
	clients: [client("tv", [deviceGrant]), client("svc", [])],
	users: [
		{ identifier: "alice", password: "correct horse battery" },
		{ identifier: "bob", password: "battery staple horse" },
		{ identifier: "carol", password: "staple battery correct" },
	],
	verificationUri: `${issuer}/device`,
	attempts,
});

let running: Started;
let base = "";
beforeAll(async () => {
	if (!areaTarget().can("device-grant")) return;
	running = await areaTarget().start(scene);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

/** What the deployment's proxy adds to every request. */
const proxied = (from: string, extra: Record<string, string> = {}) => ({
	"x-forwarded-proto": "https",
	"x-forwarded-for": from,
	"x-forwarded-host": new URL(issuer).host,
	...extra,
});
async function send(path: string, body: string, type: string, headers: Record<string, string>) {
	const res = await fetch(`${base}${path}`, {
		method: "POST",
		headers: { "content-type": type, ...headers },
		body,
	});
	return {
		status: res.status,
		headers: res.headers,
		body: (await res.json()) as Record<string, string>,
	};
}
const post = (path: string, form: Record<string, string>, headers: Record<string, string>) =>
	send(path, String(new URLSearchParams(form)), "application/x-www-form-urlencoded", headers);
const credentials = (id: string) => ({
	client_id: id,
	client_secret: `${id}-secret-0123456789abcdef`,
});
const authorize = (id = "tv") =>
	post("/oauth/device_authorization", credentials(id), proxied("198.51.100.40"));
const poll = (deviceCode: string) =>
	post(
		"/oauth/token",
		{ grant_type: deviceGrant, device_code: deviceCode, ...credentials("tv") },
		proxied("198.51.100.40"),
	);
async function login(username: string, password: string) {
	const res = await fetch(`${base}/session/login`, {
		method: "POST",
		headers: proxied("198.51.100.41", {
			"content-type": "application/x-www-form-urlencoded",
			origin: issuer,
		}),
		body: new URLSearchParams({ username, password }),
	});
	return (
		res.headers
			.getSetCookie()
			.map((c) => c.split(";")[0] ?? "")
			.find((c) => /session=/.test(c) && !/csrf/.test(c)) ?? ""
	);
}
// The verification interface is called by the deployment's page, with a JSON body.
const verify = (cookie: string, json: Record<string, string>, origin = issuer) =>
	send(
		"/oauth/device/verification",
		JSON.stringify(json),
		"application/json",
		proxied("198.51.100.41", { origin, cookie }),
	);
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe.runIf(areaTarget().can("device-grant"))("the device authorization grant", () => {
	it("gives an allowed client codes, and refuses a client not allowed the grant", async () => {
		const given = await authorize();
		expect(given.status).toBe(200);
		expect(given.body).toMatchObject({
			user_code: expect.stringMatching(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/),
			verification_uri: `${issuer}/device`,
			expires_in: 600,
			interval: 5,
		});
		const refused = await authorize("svc");
		expect([refused.status, refused.body.error]).toEqual([400, "unauthorized_client"]);
	});

	it("issues a token once to the device whose code a signed-in user approved", async () => {
		const { device_code: code = "", user_code: user = "" } = (await authorize()).body;
		expect((await poll(code)).body.error).toBe("authorization_pending");
		const cookie = await login("alice", "correct horse battery");
		const looked = await verify(cookie, { action: "lookup", user_code: user.toLowerCase() });
		expect(looked.body).toMatchObject({ client_id: "tv", scope: "read" });
		const approved = await verify(cookie, { action: "approve", user_code: user });
		expect(approved.body).toEqual({ status: "approved", client_id: "tv" });
		await wait(5100);
		const issued = await poll(code);
		expect([issued.status, issued.body.token_type]).toEqual([200, "Bearer"]);
		await wait(5100);
		expect((await poll(code)).body.error).toBe("invalid_grant");
	}, 30_000);

	it("slows a device that polls too often", async () => {
		const { device_code: code = "" } = (await authorize()).body;
		expect((await poll(code)).body.error).toBe("authorization_pending");
		expect((await poll(code)).body.error).toBe("slow_down");
	});

	it("tells a denied device, and decides a code once", async () => {
		const { device_code: code = "", user_code: user = "" } = (await authorize()).body;
		const cookie = await login("alice", "correct horse battery");
		expect((await verify(cookie, { action: "deny", user_code: user })).body.status).toBe("denied");
		const again = await verify(cookie, { action: "approve", user_code: user });
		expect([again.status, again.body.error]).toEqual([409, "already_decided"]);
		expect((await poll(code)).body.error).toBe("access_denied");
	});

	it("asks the verification interface for a session and same-origin evidence", async () => {
		const { user_code: user = "" } = (await authorize()).body;
		const none = await verify("", { action: "lookup", user_code: user });
		expect([none.status, none.body.error]).toEqual([401, "login_required"]);
		const cookie = await login("alice", "correct horse battery");
		const foreign = await verify(
			cookie,
			{ action: "lookup", user_code: user },
			"https://evil.example",
		);
		expect(foreign.status).toBe(403);
	});

	it("counts every decision a subject tries, so codes cannot be guessed", async () => {
		const cookie = await login("bob", "battery staple horse");
		for (let i = 0; i < attempts; i++) {
			const missed = await verify(cookie, { action: "lookup", user_code: "BBBB-BBBB" });
			expect([missed.status, missed.body.error]).toEqual([404, "invalid_user_code"]);
		}
		const limited = await verify(cookie, { action: "lookup", user_code: "BBBB-BBBB" });
		expect([limited.status, limited.body.error]).toEqual([429, "slow_down"]);
		expect(Number(limited.headers.get("retry-after"))).toBeGreaterThan(0);
	});
});

describe.runIf(areaTarget().can("device-grant") && areaTarget().can(auditEvents.need))(
	"the device authorization grant: audit events",
	() => {
		it("records each decision with its subject, client and scope, and a subject over its limit", async () => {
			const trail = auditEvents.of(running);
			const cookie = await login("carol", "staple battery correct");
			const decide = async (action: string) => {
				const { user_code: user = "", device_code: code = "" } = (await authorize()).body;
				const { result, events } = await trail.during(() =>
					verify(cookie, { action, user_code: user }),
				);
				expect(result.status).toBe(200);
				expect(JSON.stringify(events)).not.toMatch(new RegExp(`${user}|${code}`));
				return events;
			};
			const decided = (kind: string) => [
				{
					kind,
					at: expect.any(Number),
					subject: expect.stringMatching(/./),
					attributes: { client: "tv", scope: "read", source: "198.51.100.41" },
				},
			];
			expect(await decide("approve")).toEqual(decided("device.approved"));
			expect(await decide("deny")).toEqual(decided("device.denied"));
			for (let i = 2; i < attempts; i++) {
				await verify(cookie, { action: "lookup", user_code: "BBBB-BBBB" });
			}
			const limited = await trail.during(() =>
				verify(cookie, { action: "lookup", user_code: "BBBB-BBBB" }),
			);
			expect([limited.result.status, limited.events]).toEqual([
				429,
				[
					{
						kind: "device.rate_limited",
						at: expect.any(Number),
						subject: expect.stringMatching(/./),
						attributes: { action: "lookup", source: "198.51.100.41" },
					},
				],
			]);
		});
	},
);
