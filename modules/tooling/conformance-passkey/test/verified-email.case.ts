import { generateKeyPairSync } from "node:crypto";
import { areaTarget, sceneOf } from "@mod/conformance";
import { codeArea } from "@mod/conformance-code";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { oauthArea } from "@mod/conformance-oauth";
import { browser, issuer, password, running } from "@mod/conformance-second-factor/testing";
import {
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
} from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { passkeyArea } from "../src/main.ts";

const grantType = "urn:o3co:oauth:grant-type:webauthn";
const signing = generateKeyPairSync("ed25519");
const at = { origin: issuer };
const secret = "app-secret-0123456789abcdef";
const backChannel = {
	"x-forwarded-proto": "https",
	"x-forwarded-for": "198.51.100.42",
	"x-forwarded-host": new URL(issuer).host,
};
/** Passkey login with the gate on, over the users file: alice's email is stated verified, bob's not. */
const scene = sceneOf(
	keysArea.part({
		signing: {
			kid: "ve",
			alg: "EdDSA",
			privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	}),
	identityArea.part({
		origin: issuer,
		users: [
			{ identifier: "alice", password, emailVerified: true },
			{ identifier: "bob", password, emailVerified: false },
		],
	}),
	oauthArea.part({
		issuer,
		clients: [
			{
				id: "app",
				kind: "confidential",
				method: "client_secret_basic",
				secret,
				grants: [grantType],
				scopes: ["read"],
			},
		],
		verifiedEmail: true,
	}),
	codeArea.part({ refresh: {} }),
	passkeyArea.part({
		rpId: new URL(issuer).hostname,
		origins: [issuer],
		login: { requests: 1000, windowSeconds: 60 },
	}),
);
/** The legacy build refuses to start with the gate and passkey login, as its users file cannot find a user by subject. */
const unstartable = areaTarget().differs("email-gate-without-subject-lookup");

describe("O. verified email with passkey login over the users file", () => {
	it("starts on the new target, the legacy build refusing to", async () => {
		const started = await areaTarget().start(scene);
		if (started.kind === "running") await started.stop();
		expect(started.kind).toBe(unstartable ? "refused" : "running");
		if (started.kind === "refused") expect(started.output).toMatch(/requireEmailVerified/);
	});
});

describe.runIf(!unstartable)("H. verified email: passkey login", () => {
	const s = running(scene);
	const post = async (path: string, body: object, headers: Record<string, string> = {}) => {
		const res = await fetch(`${s.at.base}${path}`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/json", ...headers },
			body: JSON.stringify(body),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	/** Registers a passkey for `username` from a password login, then logs in with it. */
	const loginWithPasskey = async (username: string) => {
		const b = browser(() => s.at.base);
		expect((await b.login(username)).status).toBe(200);
		const offered = (await b.send("POST", "/oauth/webauthn/registration/options", {}, {}, "json"))
			.body as unknown as CreationOptions;
		const authenticator = softwareAuthenticator();
		const response = authenticator.create(offered, at);
		expect(
			(await b.send("POST", "/oauth/webauthn/registration/verify", { response }, {}, "json"))
				.status,
		).toBe(200);
		const options = (await post("/oauth/webauthn/authentication/options", { client_id: "app" }))
			.body as unknown as RequestOptions;
		return post(
			"/oauth/token",
			{ grant_type: grantType, assertion: authenticator.get(options, at), scope: "read" },
			{ authorization: `Basic ${Buffer.from(`app:${secret}`).toString("base64")}` },
		);
	};

	it("issues for a user whose email is stated verified", async () => {
		expect((await loginWithPasskey("alice")).status).toBe(200);
	});

	it("refuses a user whose email is not, saying why [rfc6749-5.2-a]", async () => {
		const res = await loginWithPasskey("bob");
		expect([res.status, res.body.error, res.body.error_description]).toEqual([
			400,
			"invalid_grant",
			"email address is not verified",
		]);
	});
});
