import { generateKeyPairSync } from "node:crypto";
import { type AreaScene, sceneOf } from "@mod/conformance";
import {
	type Deployed,
	type Deploying,
	type Instance,
	on as onDeployment,
} from "@mod/conformance/testing";
import { codeArea } from "@mod/conformance-code";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { type ClientScene, oauthArea } from "@mod/conformance-oauth";
import { browser, issuer, password } from "@mod/conformance-second-factor/testing";
import {
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
} from "@mod/webauthn/testing";
import { expect } from "vitest";
// The package's entry, which sets the area up on each target.
import { passkeyArea } from "../../main.ts";

export const grantType = "urn:o3co:oauth:grant-type:webauthn";
const signing = generateKeyPairSync("ed25519");
const user = "alice";
/** How long a challenge can be answered: the longest webauthn allows. */
export const challengeLifetimeMs = 600_000;
/** What the deployment's proxy adds to a client's own call. */
const backChannel = {
	"x-forwarded-proto": "https",
	"x-forwarded-for": "198.51.100.41",
	"x-forwarded-host": new URL(issuer).host,
};
// Allowed no refresh, so a token is all a login writes past the challenge's take.
export const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_basic",
	secret: "app-secret-0123456789abcdef",
	grants: [grantType],
	scopes: ["read"],
};

/** Passkey login at the token endpoint on the Redis store, for one client and one user. */
export const faultScene = (): AreaScene => ({
	...sceneOf(
		keysArea.part({
			signing: {
				kid: "faults",
				alg: "EdDSA",
				privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		}),
		identityArea.part({ origin: issuer, users: [{ identifier: user, password }] }),
		oauthArea.part({ issuer, clients: [app] }),
		// As the passkey login scenes compose it: the token endpoint's claims as every host takes them.
		codeArea.part({}),
		passkeyArea.part({
			rpId: new URL(issuer).hostname,
			origins: [issuer],
			// A scene's value, not the default (2m): a crash or a promotion between a challenge's two uses
			// may take a minute, and a challenge ended by its age would be refused as a used one is.
			challengeSeconds: challengeLifetimeMs / 1000,
			// A scene's value, not the default: a scene asks options a dozen times from one source.
			login: { requests: 1000, windowSeconds: 60 },
		}),
	),
	storeFaults: true,
});

/** Runs a scene on a deployment of its own, as the base does, on the passkey login's scene. */
export const on = (o: Omit<Deploying, "scene">, scene: (d: Deployed) => Promise<void>) =>
	onDeployment({ ...o, scene: faultScene() }, scene);

export type Authenticator = ReturnType<typeof softwareAuthenticator>;
export interface Answer {
	readonly status: number;
	readonly body: Readonly<Record<string, unknown>>;
}

/** An answer as a scene compares it: its status and error, or its token type where it gave a token. */
export const said = (a: Answer) => [a.status, a.body.error ?? a.body.token_type];

/**
 * The user's passkey, registered at the instance from a password login. Its authenticator keeps no
 * count, so only the challenge refuses an assertion that comes again.
 */
export async function registeredAt(i: Instance): Promise<Authenticator> {
	const b = browser(() => i.baseUrl);
	expect((await b.login(user)).status).toBe(200);
	const offered = (await b.send("POST", "/oauth/webauthn/registration/options", {}, {}, "json"))
		.body as unknown as CreationOptions;
	const authenticator = softwareAuthenticator({ countless: true });
	const response = authenticator.create(offered, { origin: issuer });
	const verified = await b.send(
		"POST",
		"/oauth/webauthn/registration/verify",
		{ response },
		{},
		"json",
	);
	expect(verified.status).toBe(200);
	return authenticator;
}

/** An assertion, the challenge it answers, and when that challenge was asked for (no later than made). */
export interface Assertion {
	readonly response: unknown;
	readonly challenge: string;
	readonly askedAt: number;
}

/** An assertion by the authenticator, for request options `app` asked of the instance just now. */
export async function assertionAt(i: Instance, authenticator: Authenticator): Promise<Assertion> {
	const askedAt = Date.now();
	const res = await fetch(`${i.baseUrl}/oauth/webauthn/authentication/options`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/json" },
		body: JSON.stringify({ client_id: app.id }),
	});
	const options = (await res.json()) as RequestOptions;
	return {
		response: authenticator.get(options, { origin: issuer }),
		challenge: options.challenge,
		askedAt,
	};
}

/** The assertion sent to the instance's token endpoint by `app`. */
export async function loginAt(i: Instance, a: Assertion): Promise<Answer> {
	const res = await fetch(`${i.baseUrl}/oauth/token`, {
		method: "POST",
		headers: {
			...backChannel,
			authorization: `Basic ${Buffer.from(`${app.id}:${app.secret}`).toString("base64")}`,
			"content-type": "application/json",
		},
		body: JSON.stringify({ grant_type: grantType, assertion: a.response, scope: "read" }),
	});
	const text = await res.text();
	let body: Record<string, unknown> = {};
	try {
		body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {}
	return { status: res.status, body };
}
