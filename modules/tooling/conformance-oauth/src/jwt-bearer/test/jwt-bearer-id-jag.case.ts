import { generateKeyPairSync, type KeyObject, randomUUID, sign } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { TrustedIssuerScene } from "../../area.ts";
import { oauthScene } from "../../main.ts";

const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const issuer = "https://issuer.example";
const tokenUrl = `${issuer}/oauth/token`;
/** An enterprise IdP whose ID-JAGs this server takes, and one whose assertions it takes as any. */
const corp = "https://corp.example";
const plain = "https://plain.example";
const api = "https://api.example";
const otherApi = "https://other.example";
const pem = (k: KeyObject, type: "pkcs8" | "spki") => k.export({ format: "pem", type }).toString();
const provider = generateKeyPairSync("ed25519");
const corpKey = generateKeyPairSync("ed25519");
const plainKey = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
const stranger = generateKeyPairSync("ed25519");
const secret = "app-secret-0123456789abcdef";

const client = (id: string, more: Record<string, unknown> = {}) => ({
	id,
	kind: "confidential" as const,
	method: "client_secret_post" as const,
	secret,
	grants: [grantType, "client_credentials"],
	scopes: ["chat.read", "chat.history", "admin"],
	defaultScopes: ["chat.read", "chat.history", "admin"],
	audiences: [api, otherApi],
	...more,
});
const plainIssuer: TrustedIssuerScene = {
	issuer: plain,
	alg: "EdDSA",
	publicPem: pem(plainKey.publicKey, "spki"),
};
/** The scene, with the ID-JAG issuer or without it: what else answers is the same either way. */
const sceneOf = (withProfile: boolean) =>
	oauthScene({
		issuer,
		keys: {
			signing: {
				kid: "ij",
				alg: "EdDSA",
				privatePem: pem(provider.privateKey, "pkcs8"),
				publicPem: pem(provider.publicKey, "spki"),
			},
		},
		clients: [client("agent"), client("other"), client("bound", { bindingRequired: true })],
		dpop: true,
		discovery: true,
		resourceIndicators: true,
		jwtBearer: {
			issuers: [
				plainIssuer,
				...(withProfile
					? [
							{
								issuer: corp,
								alg: "EdDSA",
								publicPem: pem(corpKey.publicKey, "spki"),
								profile: "id-jag",
							} as const,
						]
					: []),
			],
		},
	});

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
/** An ID-JAG the corp IdP signs for `agent`, narrow in scope and resource; `typ` as the profile names it. */
function idJag(claims: Record<string, unknown> = {}, iss = corp, key = corpKey.privateKey) {
	const now = Math.floor(Date.now() / 1000);
	const body = {
		iss,
		sub: "alice",
		aud: issuer,
		client_id: "agent",
		jti: `j-${Math.random()}`,
		iat: now,
		exp: now + 120,
		scope: "chat.read chat.history",
		resource: api,
		...claims,
	};
	const signed = `${b64({ alg: "EdDSA", typ: "oauth-id-jag+jwt" })}.${b64(body)}`;
	return `${signed}.${sign(null, Buffer.from(signed), key).toString("base64url")}`;
}
/** An assertion of no profile, of the plain issuer. */
function assertion() {
	const now = Math.floor(Date.now() / 1000);
	const body = {
		iss: plain,
		sub: "alice",
		aud: issuer,
		jti: `j-${Math.random()}`,
		iat: now,
		exp: now + 120,
	};
	const signed = `${b64({ alg: "EdDSA", typ: "JWT" })}.${b64(body)}`;
	return `${signed}.${sign(null, Buffer.from(signed), plainKey.privateKey).toString("base64url")}`;
}
/** A DPoP proof for the token endpoint by `key`, its claims changed as given. */
async function proof(key = holder, claims: Record<string, unknown> = {}) {
	return new SignJWT({
		htm: "POST",
		htu: tokenUrl,
		iat: Math.floor(Date.now() / 1000),
		jti: randomUUID(),
		...claims,
	})
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk: await exportJWK(key.publicKey) })
		.sign(key.privateKey);
}

function serving(withProfile: boolean) {
	let running: Started;
	const s = { base: "" };
	beforeAll(async () => {
		running = await areaTarget().start(sceneOf(withProfile));
		if (running.kind !== "running") throw new Error(running.output);
		s.base = running.baseUrl;
	});
	afterAll(async () => {
		if (running?.kind === "running") await running.stop();
	});
	/** A token request as `as`, with the request's parameters and a DPoP proof where given. */
	const post = async (form: Record<string, string>, as = "agent", dpop?: string) => {
		const res = await fetch(`${s.base}/oauth/token`, {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				...(dpop ? { dpop } : {}),
			},
			body: new URLSearchParams({ client_id: as, client_secret: secret, ...form }),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	const grant = (a: string, more: Record<string, string> = {}, as = "agent", dpop?: string) =>
		post({ grant_type: grantType, assertion: a, ...more }, as, dpop);
	return { s, post, grant };
}
const said = (r: { status: number; body: Record<string, unknown> }) =>
	r.status === 200 ? `200 ${r.body.token_type}` : `${r.status} ${r.body.error}`;

describe.runIf(areaTarget().can("trusted-issuers"))("C. jwt-bearer: the ID-JAG profile", () => {
	const { s, grant } = serving(true);

	it("issues within the ID-JAG, answering the scope and resource issued and no refresh token", async () => {
		const r = await grant(idJag());
		expect(r.status).toBe(200);
		expect([r.body.scope, r.body.resource]).toEqual(["chat.read chat.history", api]);
		expect(r.body).not.toHaveProperty("refresh_token");
	});

	it("is presented by the client it names alone, within its scope and resources", async () => {
		expect(said(await grant(idJag(), {}, "other"))).toBe("400 invalid_grant");
		expect(said(await grant(idJag(), { scope: "admin" }))).toBe("400 invalid_scope");
		expect(said(await grant(idJag(), { resource: otherApi }))).toBe("400 invalid_target");
		// Of another issuer's signature, or of no profile's type, none is taken as an ID-JAG.
		expect(said(await grant(idJag({}, corp, stranger.privateKey)))).toBe("400 invalid_grant");
		expect(said(await grant(idJag({}, plain, plainKey.privateKey)))).toBe("400 invalid_grant");
	});

	it("says in the metadata that it takes the profile, and names no issuer", async () => {
		for (const path of [
			"/.well-known/openid-configuration",
			"/.well-known/oauth-authorization-server",
		]) {
			const document = (await (await fetch(`${s.base}${path}`)).json()) as Record<string, unknown>;
			expect(document.authorization_grant_profiles_supported, path).toEqual([
				"urn:ietf:params:oauth:grant-profile:id-jag",
			]);
			expect(JSON.stringify(document), path).not.toContain(corp);
		}
	});

	it("is bound to the key its cnf names, by a DPoP proof the endpoint checks first", async () => {
		const jkt = await calculateJwkThumbprint(await exportJWK(holder.publicKey), "sha256");
		const bound = idJag({ cnf: { jkt } });
		expect(said(await grant(bound, {}, "agent", await proof()))).toBe("200 DPoP");
		expect(said(await grant(idJag({ cnf: { jkt } })))).toBe("400 invalid_grant");
		expect(said(await grant(idJag({ cnf: { jkt } }), {}, "agent", await proof(stranger)))).toBe(
			"400 invalid_grant",
		);
		// A proof the endpoint refuses comes first, the grant not run: the same ID-JAG goes with a new proof.
		const retried = idJag({ cnf: { jkt } });
		const wrongTarget = await proof(holder, { htu: `${issuer}/elsewhere` });
		expect(said(await grant(retried, {}, "agent", wrongTarget))).toBe("400 invalid_dpop_proof");
		expect(said(await grant(retried, {}, "agent", await proof()))).toBe("200 DPoP");
		// One naming no key is bound as the request proves, or not at all.
		expect(said(await grant(idJag(), {}, "agent", await proof()))).toBe("200 DPoP");
		expect(said(await grant(idJag()))).toBe("200 Bearer");
	});

	it("answers a client that must bind its token, and sends no proof, before the grant runs", async () => {
		const forBound = idJag({ client_id: "bound" });
		expect(said(await grant(forBound, {}, "bound"))).toBe("400 invalid_request");
		expect(said(await grant(forBound, {}, "bound", await proof()))).toBe("200 DPoP");
	});
});

describe.runIf(areaTarget().can("trusted-issuers"))(
	"C. jwt-bearer: what else answers, with an issuer taking the ID-JAG profile or none",
	() => {
		const taking = serving(true);
		const none = serving(false);
		const shape = (r: { status: number; body: Record<string, unknown> }) => ({
			status: r.status,
			type: r.body.token_type,
			keys: Object.keys(r.body).sort(),
		});

		it("answers the client credentials grant and an assertion of no profile alike", async () => {
			for (const ask of [
				(t: typeof taking) => t.post({ grant_type: "client_credentials", scope: "chat.read" }),
				(t: typeof taking) => t.grant(assertion()),
			]) {
				expect(shape(await ask(taking))).toEqual(shape(await ask(none)));
			}
		});
	},
);
