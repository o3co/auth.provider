import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { areaTarget, type Started, sceneOf } from "@mod/conformance";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ClientScene, oauthArea } from "../src/main.ts";

const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const issuer = "https://issuer.example";
const upstream = "https://idp.example";
const pem = (k: KeyObject, type: "pkcs8" | "spki") => k.export({ format: "pem", type }).toString();
const provider = generateKeyPairSync("ed25519");
const trusted = generateKeyPairSync("ed25519");
const client = (id: string, grants: string[]): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: `${id}-secret-0123456789abcdef`,
	grants,
	scopes: ["read"],
	defaultScopes: ["read"],
});
const password = "correct horse battery";

/** Tokens only for users whose email is stated verified: alice is, bob is stated not, carol states nothing. */
const scene = (jwtBearer: boolean) =>
	sceneOf(
		keysArea.part({
			signing: {
				kid: "ve",
				alg: "EdDSA",
				privatePem: pem(provider.privateKey, "pkcs8"),
				publicPem: pem(provider.publicKey, "spki"),
			},
		}),
		identityArea.part({
			origin: issuer,
			users: [
				{ identifier: "alice", password, subject: "s-alice", emailVerified: true },
				{ identifier: "bob", password, subject: "s-bob", emailVerified: false },
				{ identifier: "carol", password, subject: "s-carol" },
			],
		}),
		oauthArea.part({
			issuer,
			clients: [client("app", [grantType]), client("svc", ["client_credentials"])],
			verifiedEmail: true,
			...(jwtBearer
				? {
						jwtBearer: {
							issuers: [
								{ issuer: upstream, alg: "EdDSA", publicPem: pem(trusted.publicKey, "spki") },
							],
						},
					}
				: {}),
		}),
	);

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
function assertion(sub: string): string {
	const now = Math.floor(Date.now() / 1000);
	const body = {
		iss: upstream,
		sub,
		aud: issuer,
		iat: now,
		exp: now + 120,
		jti: `j-${Math.random()}`,
	};
	const input = `${b64({ alg: "EdDSA", typ: "JWT" })}.${b64(body)}`;
	return `${input}.${sign(null, Buffer.from(input), trusted.privateKey).toString("base64url")}`;
}

async function post(base: string, id: string, form: Record<string, string>) {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: {
			"content-type": "application/x-www-form-urlencoded",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "198.51.100.30",
		},
		body: new URLSearchParams({
			client_id: id,
			client_secret: `${id}-secret-0123456789abcdef`,
			...form,
		}),
	});
	return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

function running(jwtBearer: boolean) {
	let started: Started;
	let base = "";
	beforeAll(async () => {
		started = await areaTarget().start(scene(jwtBearer));
		if (started.kind !== "running") throw new Error(`refused:\n${started.output}`);
		base = started.baseUrl;
	});
	afterAll(async () => {
		if (started?.kind === "running") await started.stop();
	});
	return () => base;
}

describe("C. verified email: client credentials", () => {
	const base = running(false);

	it("still issues to a client, which names no user", async () => {
		const res = await post(base(), "svc", { grant_type: "client_credentials" });
		expect(res.status).toBe(200);
		expect(res.body.token_type).toBe("Bearer");
	});
});

describe.runIf(areaTarget().can("trusted-issuers"))("C. verified email: jwt-bearer", () => {
	const base = running(true);

	it("issues for a subject whose email is stated verified", async () => {
		const res = await post(base(), "app", {
			grant_type: grantType,
			assertion: assertion("s-alice"),
		});
		expect(res.status).toBe(200);
	});

	it.each(["s-bob", "s-carol", "s-nobody"])("refuses %s as invalid_grant", async (subject) => {
		const res = await post(base(), "app", { grant_type: grantType, assertion: assertion(subject) });
		expect([res.status, res.body.error]).toEqual([400, "invalid_grant"]);
		expect(res.body).not.toHaveProperty("access_token");
	});

	it.skipIf(areaTarget().differs("email-refusal-description"))(
		"tells the client the email is not verified",
		async () => {
			const res = await post(base(), "app", {
				grant_type: grantType,
				assertion: assertion("s-bob"),
			});
			expect(res.body.error_description).toBe("email address is not verified");
		},
	);
});
