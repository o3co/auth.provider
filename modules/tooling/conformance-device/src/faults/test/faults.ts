import { generateKeyPairSync } from "node:crypto";
import type { AreaScene } from "@mod/conformance";
import {
	type Deployed,
	type Deploying,
	type Instance,
	on as onDeployment,
} from "@mod/conformance/testing";
import type { ClientScene } from "@mod/conformance-oauth";
// The package's entry, which sets the area up on each target.
import { deviceScene } from "../../main.ts";

export const issuer = "https://issuer.example";
export const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code";
const pair = generateKeyPairSync("ed25519");
const alice = { identifier: "alice", password: "correct horse battery" };
export const tv: ClientScene = {
	id: "tv",
	kind: "confidential",
	method: "client_secret_post",
	secret: "tv-secret-0123456789abcdef",
	grants: [deviceGrant],
	scopes: ["read"],
	defaultScopes: ["read"],
};

/** The device grant on the Redis store, for one client and one user. */
export const faultScene = (): AreaScene => ({
	...deviceScene({
		issuer,
		keys: {
			signing: {
				kid: "faults",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		clients: [tv],
		users: [alice],
		verificationUri: `${issuer}/device`,
		// A scene's value, not the default (5): a scene looks up and decides up to five times as alice in one window.
		attempts: 20,
	}),
	storeFaults: true,
});

/** Runs a scene on a deployment of its own, as the base does, on the device grant's scene. */
export const on = (o: Omit<Deploying, "scene">, scene: (d: Deployed) => Promise<void>) =>
	onDeployment({ ...o, scene: faultScene() }, scene);

/** An answer: its status and JSON body. */
export interface Answer {
	readonly status: number;
	readonly body: Readonly<Record<string, unknown>>;
}

/** What the deployment's proxy adds to every request. */
const proxied = (from: string, extra: Record<string, string> = {}) => ({
	"x-forwarded-proto": "https",
	"x-forwarded-for": from,
	"x-forwarded-host": new URL(issuer).host,
	...extra,
});

async function send(
	i: Instance,
	path: string,
	body: string,
	type: string,
	headers: Record<string, string>,
): Promise<Answer> {
	const res = await fetch(`${i.baseUrl}${path}`, {
		method: "POST",
		headers: { "content-type": type, ...headers },
		body,
	});
	const text = await res.text();
	let parsed: Record<string, unknown> = {};
	try {
		parsed = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {}
	return { status: res.status, body: parsed };
}

const formAt = (i: Instance, path: string, form: Record<string, string>) =>
	send(
		i,
		path,
		String(new URLSearchParams(form)),
		"application/x-www-form-urlencoded",
		proxied("198.51.100.40"),
	);
const credentials = { client_id: tv.id, client_secret: tv.secret ?? "" };

/** A device's two codes. */
export interface Device {
	readonly deviceCode: string;
	readonly userCode: string;
}

/** A device the instance authorizes for `tv`. */
export async function deviceAt(i: Instance): Promise<Device> {
	const given = await formAt(i, "/oauth/device_authorization", credentials);
	const { device_code: deviceCode, user_code: userCode } = given.body;
	if (given.status !== 200 || typeof deviceCode !== "string" || typeof userCode !== "string")
		throw new Error(`no device authorized: ${given.status} ${JSON.stringify(given.body)}`);
	return { deviceCode, userCode };
}

/** Alice's session cookie, from a login at the instance. */
export async function loginAt(i: Instance): Promise<string> {
	const res = await fetch(`${i.baseUrl}/session/login`, {
		method: "POST",
		headers: proxied("198.51.100.41", {
			"content-type": "application/x-www-form-urlencoded",
			origin: issuer,
		}),
		body: new URLSearchParams({ username: alice.identifier, password: alice.password }),
	});
	const cookie = res.headers
		.getSetCookie()
		.map((c) => c.split(";")[0] ?? "")
		.find((c) => /session=/.test(c) && !/csrf/.test(c));
	if (!cookie) throw new Error(`no session at login: ${res.status}`);
	return cookie;
}

/** Alice's lookup of the device, or her decision on it, sent to the instance's verification interface as its page sends it. */
export const decideAt = (
	i: Instance,
	cookie: string,
	action: "lookup" | "approve" | "deny",
	d: Device,
): Promise<Answer> =>
	send(
		i,
		"/oauth/device/verification",
		JSON.stringify({ action, user_code: d.userCode }),
		"application/json",
		proxied("198.51.100.41", { origin: issuer, cookie }),
	);

/** The device's poll at the instance's token endpoint. */
export const pollAt = (i: Instance, d: Device): Promise<Answer> =>
	formAt(i, "/oauth/token", { grant_type: deviceGrant, device_code: d.deviceCode, ...credentials });

/**
 * A device the instance authorizes and alice approves there, not yet polled: its first poll is never
 * too soon, so it takes the approval at once.
 */
export async function approvedAt(i: Instance): Promise<Device> {
	const d = await deviceAt(i);
	const decided = await decideAt(i, await loginAt(i), "approve", d);
	if (decided.status !== 200) throw new Error(`not approved: ${decided.status}`);
	return d;
}

/** An answer as a scene compares it: its status and error, or its token type where it gave a token. */
export const said = (a: Answer) => [a.status, a.body.error ?? a.body.token_type];
