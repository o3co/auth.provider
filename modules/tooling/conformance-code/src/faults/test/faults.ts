import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import type { AreaScene } from "@mod/conformance";
import {
	type Deployed,
	type Deploying,
	type Instance,
	on as onDeployment,
} from "@mod/conformance/testing";
import type { ClientScene } from "@mod/conformance-oauth";
// The package's entry, which sets the area up on each target.
import { type CodeScene, codeScene } from "../../main.ts";
import { backChannel, browserAt } from "../../testing.ts";

export const issuer = "https://issuer.example";
export const callback = "https://app.example/cb";
const pair = generateKeyPairSync("ed25519");
const alice = { username: "alice", password: "alice-horse-battery-staple" };
export const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "app-secret-0123456789abcdef",
	grants: ["authorization_code", "refresh_token"],
	scopes: ["openid"],
	defaultScopes: ["openid"],
	redirectUris: [callback],
	firstParty: true,
};

/** The code flow on the Redis store, one client and one user, with what a scene adds. */
export const faultScene = (more: Partial<CodeScene> = {}): AreaScene =>
	codeScene({
		issuer,
		keys: {
			signing: {
				kid: "faults",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		// The refresh grant only where refresh is composed, which boot otherwise refuses.
		clients: [more.refresh ? app : { ...app, grants: ["authorization_code"] }],
		users: [{ identifier: alice.username, password: alice.password }],
		...more,
		storeFaults: true,
	});

/** Runs a scene on a deployment of its own, as the base does, on the code flow's scene unless it names another. */
export const on = (
	o: Omit<Deploying, "scene"> & { readonly scene?: AreaScene },
	scene: (d: Deployed) => Promise<void>,
) => onDeployment({ ...o, scene: o.scene ?? faultScene() }, scene);

/** A verifier of its own, so a scene tells its code's writes from any other by the challenge. */
export function pkce() {
	const verifier = randomBytes(32).toString("base64url");
	return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

export interface Code {
	readonly code: string;
	readonly verifier: string;
	readonly challenge: string;
}

/** A browser behind the instance's proxy that logs in there. */
export const browserOn = (i: Instance) => browserAt(() => i.baseUrl, issuer, alice);

/** A code the instance gives a browser logged in at it (a new one unless given), for `app`. */
export async function codeAt(i: Instance, browser = browserOn(i)): Promise<Code> {
	const { verifier, challenge } = pkce();
	const res = await browser.authorize({
		response_type: "code",
		client_id: app.id,
		redirect_uri: callback,
		state: "s1",
		scope: "openid",
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	const code = res.at?.searchParams.get("code");
	if (!code) throw new Error(`the authorization endpoint gave no code: ${res.status}`);
	return { code, verifier, challenge };
}

/** A token endpoint's answer: its status and JSON body, or none where the instance cut it short. */
export interface Answer {
	readonly status: number;
	readonly body: Readonly<Record<string, unknown>>;
}

/** A request to the instance's token endpoint as `app`. */
export async function tokenAt(
	i: Instance,
	form: Readonly<Record<string, string>>,
): Promise<Answer> {
	const res = await fetch(`${i.baseUrl}/oauth/token`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ ...form, client_id: app.id, client_secret: app.secret ?? "" }),
	});
	const text = await res.text();
	let body: Record<string, unknown> = {};
	try {
		body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {}
	return { status: res.status, body };
}

export const redeemAt = (i: Instance, c: Code) =>
	tokenAt(i, {
		grant_type: "authorization_code",
		code: c.code,
		redirect_uri: callback,
		code_verifier: c.verifier,
	});

/** An answer as a scene compares it: its status and error, or its token type where it gave a token. */
export const said = (a: Answer) => [a.status, a.body.error ?? a.body.token_type];

export const refreshAt = (i: Instance, token: string) =>
	tokenAt(i, { grant_type: "refresh_token", refresh_token: token });
