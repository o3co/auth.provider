import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { deviceScene } from "../src/main.ts";

const issuer = "https://issuer.example";
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code";
const password = "correct horse battery";
const pair = generateKeyPairSync("ed25519");
const tv: ClientScene = {
	id: "tv",
	kind: "confidential",
	method: "client_secret_post",
	secret: "tv-secret-0123456789abcdef",
	grants: [deviceGrant],
	scopes: ["read"],
	defaultScopes: ["read"],
};
/** alice's email is stated verified, bob's not. */
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
	clients: [tv],
	users: [
		{ identifier: "alice", password, emailVerified: true },
		{ identifier: "bob", password, emailVerified: false },
	],
	verificationUri: `${issuer}/device`,
	verifiedEmail: true,
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
	return { status: res.status, body: (await res.json()) as Record<string, string> };
}
const form = (path: string, fields: Record<string, string>) =>
	send(
		path,
		String(new URLSearchParams({ ...fields, client_id: tv.id, client_secret: tv.secret ?? "" })),
		"application/x-www-form-urlencoded",
		proxied("198.51.100.40"),
	);
const codes = async () => (await form("/oauth/device_authorization", {})).body;
const poll = (deviceCode: string) =>
	form("/oauth/token", { grant_type: deviceGrant, device_code: deviceCode });
async function login(username: string) {
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
const verify = (cookie: string, json: Record<string, string>) =>
	send(
		"/oauth/device/verification",
		JSON.stringify(json),
		"application/json",
		proxied("198.51.100.41", { origin: issuer, cookie }),
	);

describe.runIf(areaTarget().can("device-grant"))("K. verified email: device approval", () => {
	it("refuses bob's approval as access_denied, and leaves the device pending", async () => {
		const { device_code: code = "", user_code: user = "" } = await codes();
		const cookie = await login("bob");
		const looked = await verify(cookie, { action: "lookup", user_code: user });
		expect(looked.body).toMatchObject({ client_id: "tv", scope: "read" });
		const approved = await verify(cookie, { action: "approve", user_code: user });
		expect([approved.status, approved.body.error, approved.body.error_description]).toEqual([
			403,
			"access_denied",
			"email address is not verified",
		]);
		expect((await poll(code)).body.error).toBe("authorization_pending");
	});

	it("lets bob deny a code", async () => {
		const { user_code: user = "" } = await codes();
		const cookie = await login("bob");
		expect((await verify(cookie, { action: "deny", user_code: user })).body.status).toBe("denied");
	});

	it("issues to the device alice approved", async () => {
		const { device_code: code = "", user_code: user = "" } = await codes();
		const cookie = await login("alice");
		const approved = await verify(cookie, { action: "approve", user_code: user });
		expect(approved.body).toEqual({ status: "approved", client_id: "tv" });
		const issued = await poll(code);
		expect([issued.status, issued.body.token_type]).toEqual([200, "Bearer"]);
	});
});
