import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import type { AreaScene } from "@mod/conformance";
import {
	type Deployed,
	type Deploying,
	type Instance,
	on as onDeployment,
} from "@mod/conformance/testing";
import { type CodeScene, codeScene } from "@mod/conformance-code";
import { browserAt } from "@mod/conformance-code/testing";
import type { ClientScene } from "@mod/conformance-oauth";
// The package's entry, which sets the area up on each target.
import { exchangeArea } from "../../main.ts";

export const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const api = "https://api.example";
export const exchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
const accessType = "urn:ietf:params:oauth:token-type:access_token";
const pair = generateKeyPairSync("ed25519");
const secret = "app-secret-0123456789abcdef";

export const users = {
	alice: { username: "alice", password: "alice-horse-battery-staple", subject: "user-alice" },
	bob: { username: "bob", password: "bob-horse-battery-staple", subject: "user-bob" },
};
export type User = (typeof users)[keyof typeof users];

/** The client that redeems a user's code and exchanges the access token it was given. */
export const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret,
	grants: ["authorization_code", exchangeGrant],
	scopes: ["openid", "read"],
	defaultScopes: ["read"],
	redirectUris: [callback],
	firstParty: true,
	audiences: [api],
};

/** The code flow with token exchange on the Redis store, for one client and two users, with what a scene adds. */
export function faultScene(more: Partial<CodeScene> = {}): AreaScene {
	const built = codeScene({
		issuer,
		keys: {
			signing: {
				kid: "faults",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		clients: [app],
		users: Object.values(users).map((u) => ({
			identifier: u.username,
			password: u.password,
			subject: u.subject,
		})),
		...more,
		storeFaults: true,
	});
	const [exchange, part] = exchangeArea.part({});
	return { ...built, parts: { ...built.parts, [exchange]: part } };
}

/** Runs a scene on a deployment of its own, as the base does, on the token exchange's scene unless it names another. */
export const on = (
	o: Omit<Deploying, "scene"> & { readonly scene?: AreaScene },
	scene: (d: Deployed) => Promise<void>,
) => onDeployment({ ...o, scene: o.scene ?? faultScene() }, scene);

/** An answer: its status and JSON body. */
export interface Answer {
	readonly status: number;
	readonly body: Readonly<Record<string, unknown>>;
}

/** A form posted by `app` to the instance, as its proxy forwards a client's own call. */
async function postAt(i: Instance, path: string, form: Record<string, string>): Promise<Answer> {
	const res = await fetch(`${i.baseUrl}${path}`, {
		method: "POST",
		headers: {
			"x-forwarded-proto": "https",
			"x-forwarded-for": "198.51.100.21",
			"content-type": "application/x-www-form-urlencoded",
		},
		body: new URLSearchParams({ ...form, client_id: app.id, client_secret: secret }),
	});
	const text = await res.text();
	let body: Record<string, unknown> = {};
	try {
		body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {}
	return { status: res.status, body };
}

/** The access token `app` is given for the user, from a code of her login at the instance. */
export async function accessAt(i: Instance, user: User): Promise<string> {
	const browser = browserAt(() => i.baseUrl, issuer, user);
	const verifier = randomBytes(32).toString("base64url");
	const asked = await browser.authorize({
		response_type: "code",
		client_id: app.id,
		redirect_uri: callback,
		state: "s",
		scope: "openid read",
		code_challenge: createHash("sha256").update(verifier).digest("base64url"),
		code_challenge_method: "S256",
	});
	const code = asked.at?.searchParams.get("code");
	if (!code) throw new Error(`no code: ${asked.status}`);
	const redeemed = await postAt(i, "/oauth/token", {
		grant_type: "authorization_code",
		code,
		redirect_uri: callback,
		code_verifier: verifier,
	});
	const token = redeemed.body.access_token;
	if (redeemed.status !== 200 || typeof token !== "string")
		throw new Error(`no token: ${redeemed.status} ${JSON.stringify(redeemed.body)}`);
	return token;
}

/** The access token exchanged by `app` at the instance, as the subject token. */
export const exchangeAt = (i: Instance, token: string) =>
	postAt(i, "/oauth/token", {
		grant_type: exchangeGrant,
		subject_token: token,
		subject_token_type: accessType,
	});

/** An answer as a scene compares it: its status and error, or its token type where it gave a token. */
export const said = (a: Answer) => [a.status, a.body.error ?? a.body.token_type];
