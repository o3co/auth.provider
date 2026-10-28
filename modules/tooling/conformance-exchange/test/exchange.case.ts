import { createHash, generateKeyPairSync, type KeyObject, randomUUID } from "node:crypto";
import { type AreaScene, areaTarget, faultyTarget, type Started } from "@mod/conformance";
import { browserAt } from "@mod/conformance-code/testing";
import type { ClientScene } from "@mod/conformance-oauth";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ExchangeScene, exchangeScene } from "../src/main.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const api = "https://api.example";
const admin = "https://admin.example";
const exchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
const accessType = "urn:ietf:params:oauth:token-type:access_token";
const signing = generateKeyPairSync("ed25519");
const forger = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
const thief = generateKeyPairSync("ed25519");
type Pair = { publicKey: KeyObject; privateKey: KeyObject };
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const secretOf = (id: string) => `${id}-secret-0123456789abcdef`;
const client = (id: string, grants: string[], extra: Partial<ClientScene> = {}): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: secretOf(id),
	grants,
	scopes: ["openid", "read", "write"],
	defaultScopes: ["read", "write"],
	audiences: [api, admin],
	...extra,
});
const coded = { redirectUris: [callback], firstParty: true };
/** Unlike either system's default, so the limit is seen to come from the scene. */
const maxActorDepth = 1;
/** Both systems' access-token lifetime: the one cap both take, as neither issues past it. */
const maxLifetimeSeconds = 3600;
const given: ExchangeScene = {
	issuer,
	keys: {
		signing: {
			kid: "te",
			alg: "EdDSA",
			privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		client(
			"gateway",
			["authorization_code", "refresh_token", "client_credentials", exchangeGrant],
			coded,
		),
		client("direct", ["authorization_code", exchangeGrant], coded),
		client("other", ["client_credentials", exchangeGrant], {
			audiences: ["https://other.example"],
		}),
		client("svc", ["client_credentials"]),
		// Allowed the issuer's audience too, so a refusal of it comes from the subject token alone.
		client("keeper", ["authorization_code", exchangeGrant], {
			...coded,
			audiences: [api, issuer],
		}),
		{ id: "spa", kind: "public", method: "none", grants: [exchangeGrant], scopes: ["read"] },
	],
	users: [{ identifier: "alice", password: "correct horse battery" }],
	dpop: true,
	maxActorDepth,
	maxLifetimeSeconds,
};
/** Most scenes exchange tokens of a refresh family, which carry no session. */
const scene = exchangeScene({ ...given, sessionless: true });

let base = "";
/** Starts the scene for the suite it is called in, at the base the calls below use. */
function startedFor(asked: AreaScene) {
	let running: Started;
	beforeAll(async () => {
		running = await areaTarget().start(asked);
		if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
		base = running.baseUrl;
	});
	afterAll(async () => {
		if (running?.kind === "running") await running.stop();
	});
}

const browser = browserAt(() => base, issuer, {
	username: "alice",
	password: "correct horse battery",
});
/** What the deployment's proxy adds to a client's own call. */
const backChannel = {
	"x-forwarded-proto": "https",
	"x-forwarded-for": "198.51.100.21",
	"x-forwarded-host": new URL(issuer).host,
};
/** The client's address the proxy forwards. */
let source = backChannel["x-forwarded-for"];
const proofBy = async (key: Pair) =>
	new SignJWT({
		htm: "POST",
		htu: `${issuer}/oauth/token`,
		iat: Math.floor(Date.now() / 1000),
		jti: randomUUID(),
	})
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk: await exportJWK(key.publicKey) })
		.sign(key.privateKey);
async function post(
	path: string,
	as: string,
	form: Record<string, string> | [string, string][],
	key?: Pair,
) {
	const res = await fetch(`${base}${path}`, {
		method: "POST",
		headers: {
			...backChannel,
			"x-forwarded-for": source,
			"content-type": "application/x-www-form-urlencoded",
			...(key ? { dpop: await proofBy(key) } : {}),
		},
		body: new URLSearchParams([
			...(Array.isArray(form) ? form : Object.entries(form)),
			["client_id", as],
			...(as === "spa" ? [] : [["client_secret", secretOf(as)]]),
		]),
	});
	const text = await res.text();
	return { status: res.status, body: (text ? JSON.parse(text) : {}) as Record<string, string> };
}
const claimsOf = (jwt: string | undefined) =>
	JSON.parse(Buffer.from((jwt ?? "").split(".")[1] ?? "", "base64url").toString()) as Record<
		string,
		unknown
	>;
const refusal = (answer: { status: number; body: Record<string, string> }) => [
	answer.status,
	answer.body.error,
];

/** A token of the client's own, which names it. */
const own = async (as: string, extra: Record<string, string> = {}, key?: Pair) =>
	(await post("/oauth/token", as, { grant_type: "client_credentials", ...extra }, key)).body;
/** Logs alice in, asks for a code and redeems it, as the given client. */
async function tokensFor(as = "gateway") {
	const res = await browser.authorize({
		response_type: "code",
		client_id: as,
		redirect_uri: callback,
		state: "s1",
		scope: "openid read write",
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	const code = res.at?.searchParams.get("code") ?? "";
	return (
		await post("/oauth/token", as, {
			grant_type: "authorization_code",
			code,
			redirect_uri: callback,
			code_verifier: verifier,
		})
	).body;
}
const exchange = (
	as: string,
	subject: string | undefined,
	extra: Record<string, string> = {},
	key?: Pair,
) =>
	post(
		"/oauth/token",
		as,
		{
			grant_type: exchangeGrant,
			subject_token: subject ?? "",
			subject_token_type: accessType,
			...extra,
		},
		key,
	);
const actedBy = (actor: string | undefined) => ({
	actor_token: actor ?? "",
	actor_token_type: accessType,
});
/** Asked by the client the token was issued to, which may see it whatever its audience. */
const active = async (token: string | undefined, as = "gateway") =>
	(await post("/oauth/introspect", as, { token: token ?? "" })).body.active;

describe("token exchange of tokens no session holds", () => {
	startedFor(scene);

	describe("token exchange", () => {
		it("gives an allowed client an access token for its own token, narrowed to the scope it asks [rfc8693-2.2.1-a] [rfc8693-2.2.1-b] [rfc8693-2.2.1-c] [rfc6749-5.1-a]", async () => {
			const subject = await tokensFor();
			const issued = await exchange("gateway", subject.access_token, { scope: "read" });
			expect(issued.status).toBe(200);
			expect(issued.body).toMatchObject({
				issued_token_type: accessType,
				token_type: "Bearer",
				scope: "read",
			});
			expect(issued.body).not.toHaveProperty("refresh_token");
			expect(issued.body).not.toHaveProperty("id_token");
			const claims = claimsOf(issued.body.access_token);
			expect(claims.sub).toBe(claimsOf(subject.access_token).sub);
			expect(claims.act).toBeUndefined();
			expect(Number(claims.exp)).toBeLessThanOrEqual(Number(claimsOf(subject.access_token).exp));
			expect(await active(issued.body.access_token)).toBe(true);
		});

		it("carries the subject's authentication, as its own token had it", async () => {
			const { access_token: token } = await tokensFor();
			const subject = claimsOf(token);
			const issued = claimsOf((await exchange("gateway", token)).body.access_token);
			expect([issued.amr, issued.auth_time === undefined]).toEqual([
				subject.amr,
				subject.auth_time === undefined,
			]);
		});

		it("keeps the subject with an actor token, and names the actor", async () => {
			const subject = await tokensFor();
			const actor = await own("gateway");
			const issued = await exchange("gateway", subject.access_token, actedBy(actor.access_token));
			expect(issued.status).toBe(200);
			const claims = claimsOf(issued.body.access_token);
			expect(claims.sub).toBe(claimsOf(subject.access_token).sub);
			expect(claims.act).toEqual({ sub: claimsOf(actor.access_token).sub });
		});
	});

	describe("token exchange: the lifetime asked", () => {
		// A source of its own, so these requests stay within the token endpoint's limit per source.
		beforeAll(() => {
			source = "198.51.100.22";
		});
		afterAll(() => {
			source = backChannel["x-forwarded-for"];
		});
		const lifetimeOf = (jwt: string | undefined) => {
			const claims = claimsOf(jwt);
			return Number(claims.exp) - Number(claims.iat);
		};

		it("issues for a shorter expires_in, and answers that lifetime [rfc8693-2.2.1-d] [rfc6749-5.1-b]", async () => {
			const { access_token: token } = await tokensFor();
			const issued = await exchange("gateway", token, { expires_in: "60" });
			expect(issued.status).toBe(200);
			expect(lifetimeOf(issued.body.access_token)).toBe(60);
			expect(Number(issued.body.expires_in)).toBeGreaterThan(0);
			expect(Number(issued.body.expires_in)).toBeLessThanOrEqual(60);
		});

		it("cuts a longer expires_in to the cap, never refusing it", async () => {
			const { access_token: token } = await tokensFor();
			for (const asked of ["7200", "9999999999"]) {
				const issued = await exchange("gateway", token, { expires_in: asked });
				expect(issued.status).toBe(200);
				expect(lifetimeOf(issued.body.access_token)).toBeLessThanOrEqual(maxLifetimeSeconds);
				expect(Number(issued.body.expires_in)).toBeLessThanOrEqual(maxLifetimeSeconds);
				expect(Number(claimsOf(issued.body.access_token).exp)).toBeLessThanOrEqual(
					Number(claimsOf(token).exp),
				);
			}
		});

		it("refuses an expires_in that is not a positive whole number of seconds, or sent twice [rfc6749-3.2-d] [rfc8693-2.2.2-a] [rfc8693-2.2.2-b] [rfc6749-5.2-a]", async () => {
			const { access_token: token } = await tokensFor();
			for (const asked of ["soon", "0", "-60", "1.5"]) {
				expect(refusal(await exchange("gateway", token, { expires_in: asked }))).toEqual([
					400,
					"invalid_request",
				]);
			}
			const twice = await post("/oauth/token", "gateway", [
				["grant_type", exchangeGrant],
				["subject_token", token ?? ""],
				["subject_token_type", accessType],
				["expires_in", "60"],
				["expires_in", "120"],
			]);
			expect(refusal(twice)).toEqual([400, "invalid_request"]);
		});
	});

	describe("token exchange: a binding washed off [guarantee-6-b]", () => {
		it("refuses a DPoP-bound subject token without a proof, or with another key's [rfc8693-2.2.2-a] [rfc8693-2.2.2-b] [rfc6749-5.2-a]", async () => {
			const bound = await own("gateway", {}, holder);
			expect(bound.token_type).toBe("DPoP");
			expect(refusal(await exchange("gateway", bound.access_token))).toEqual([
				400,
				"invalid_request",
			]);
			expect(refusal(await exchange("gateway", bound.access_token, {}, thief))).toEqual([
				400,
				"invalid_request",
			]);
		});

		it("binds the token it issues to the same key [rfc9449-5-b] [rfc9449-6.1-a]", async () => {
			const bound = await own("gateway", {}, holder);
			const issued = await exchange("gateway", bound.access_token, {}, holder);
			expect([issued.status, issued.body.token_type]).toEqual([200, "DPoP"]);
			const thumbprint = await calculateJwkThumbprint(await exportJWK(holder.publicKey));
			expect(claimsOf(issued.body.access_token).cnf).toEqual({ jkt: thumbprint });
		});

		it("refuses a DPoP-bound actor token without a proof [rfc8693-2.2.2-a] [rfc8693-2.2.2-b] [rfc6749-5.2-a]", async () => {
			const subject = await own("gateway");
			const actor = await own("gateway", {}, holder);
			const answer = await exchange("gateway", subject.access_token, actedBy(actor.access_token));
			expect(refusal(answer)).toEqual([400, "invalid_request"]);
		});

		it("never issues a bearer token for an actor that proved its DPoP key [rfc9449-5-b]", async () => {
			const subject = await tokensFor();
			const actor = await own("gateway", {}, holder);
			const issued = await exchange(
				"gateway",
				subject.access_token,
				actedBy(actor.access_token),
				holder,
			);
			expect([issued.status, issued.body.token_type]).toEqual([200, "DPoP"]);
			expect(claimsOf(issued.body.access_token).cnf).toBeDefined();
		});
	});

	describe("token exchange: a forged actor", () => {
		it("refuses an actor token it cannot verify [rfc8693-2.1-h] [rfc8693-2.2.2-a] [rfc8693-2.2.2-b] [rfc6749-5.2-a]", async () => {
			const subject = await tokensFor();
			const now = Math.floor(Date.now() / 1000);
			const forged = await new SignJWT({
				iss: issuer,
				sub: "mallory",
				aud: api,
				client_id: "gateway",
				azp: "gateway",
				scope: "read",
				iat: now,
				exp: now + 600,
				jti: randomUUID(),
			})
				.setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid: "te" })
				.sign(forger.privateKey);
			const answer = await exchange("gateway", subject.access_token, actedBy(forged));
			expect(refusal(answer)).toEqual([400, "invalid_request"]);
		});

		it("refuses an actor token that does not name the calling client [rfc8693-2.2.2-a] [rfc8693-2.2.2-b] [rfc6749-5.2-a]", async () => {
			const subject = await tokensFor();
			const actor = await own("other");
			const answer = await exchange("gateway", subject.access_token, actedBy(actor.access_token));
			expect(refusal(answer)).toEqual([400, "invalid_request"]);
		});

		it("refuses an actor past the chain's limit, and drops the chain without an actor [rfc8693-2.2.2-a] [rfc8693-2.2.2-b] [rfc6749-5.2-a]", async () => {
			const actor = await own("gateway");
			const delegated = await exchange(
				"gateway",
				(await tokensFor()).access_token,
				actedBy(actor.access_token),
			);
			expect(delegated.status).toBe(200);
			const deeper = await exchange(
				"gateway",
				delegated.body.access_token,
				actedBy((await own("gateway")).access_token),
			);
			expect(refusal(deeper)).toEqual([400, "invalid_request"]);
			const alone = await exchange("gateway", delegated.body.access_token);
			expect(alone.status).toBe(200);
			expect(claimsOf(alone.body.access_token).act).toBeUndefined();
		});
	});

	describe("token exchange: a missed revocation", () => {
		it("refuses a revoked access token [rfc7009-2-b] [rfc8693-2.1-g] [rfc8693-2.2.2-a] [rfc8693-2.2.2-b] [rfc6749-5.2-a]", async () => {
			const { access_token: token = "" } = await tokensFor();
			const revoked = await post("/oauth/revoke", "gateway", {
				token,
				token_type_hint: "access_token",
			});
			expect(revoked.status).toBe(200);
			expect(refusal(await exchange("gateway", token))).toEqual([400, "invalid_request"]);
		});

		it("ends the tokens it issued with the subject's family, and refuses the family's tokens after [rfc7662-4-d] [rfc8693-2.1-g] [rfc8693-2.2.2-a] [rfc8693-2.2.2-b] [rfc6749-5.2-a]", async () => {
			const subject = await tokensFor();
			const issued = await exchange("gateway", subject.access_token);
			expect(await active(issued.body.access_token)).toBe(true);
			const revoked = await post("/oauth/revoke", "gateway", {
				token: subject.refresh_token ?? "",
				token_type_hint: "refresh_token",
			});
			expect(revoked.status).toBe(200);
			expect(refusal(await exchange("gateway", subject.access_token))).toEqual([
				400,
				"invalid_request",
			]);
			expect(await active(issued.body.access_token)).toBe(false);
		});

		it("ends the tokens it issued at logout", async () => {
			browser.forget();
			const subject = await tokensFor();
			const issued = await exchange("gateway", subject.access_token);
			expect(await active(issued.body.access_token)).toBe(true);
			expect(await browser.logout()).toBe(200);
			expect(await active(issued.body.access_token)).toBe(false);
		});
	});

	describe("token exchange: refusals", () => {
		it("refuses a public client as an unauthenticated one", async () => {
			const { access_token: token } = await own("gateway");
			expect(refusal(await exchange("spa", token))).toEqual([401, "invalid_client"]);
		});

		it("refuses a client not allowed the grant [rfc6749-5.2-a]", async () => {
			const { access_token: token } = await own("svc");
			expect(refusal(await exchange("svc", token))).toEqual([400, "unauthorized_client"]);
		});

		it("never widens the scope past the subject token's [rfc8693-2.2.2-a] [rfc6749-5.2-a]", async () => {
			const { access_token: token } = await own("gateway", { scope: "read" });
			expect(refusal(await exchange("gateway", token, { scope: "read write" }))).toEqual([
				400,
				"invalid_scope",
			]);
		});

		it("never widens the audience past the subject token's, and takes only a resource it issues for [rfc8693-2.2.2-a] [rfc8693-2.2.2-c] [rfc6749-5.2-a]", async () => {
			const { access_token: token } = await own("gateway");
			const held = [claimsOf(token).aud].flat();
			const outside = [api, admin].find((a) => !held.includes(a)) ?? "";
			expect(refusal(await exchange("gateway", token, { audience: outside }))).toEqual([
				400,
				"invalid_target",
			]);
			expect(
				refusal(await exchange("gateway", token, { resource: "https://other.example" })),
			).toEqual([400, "invalid_target"]);
		});

		it.skipIf(areaTarget().differs("token-for-the-issuer"))(
			"takes none of what the issuer added to an openid subject token's aud: no token for the issuer from it [rfc8693-2.2.2-a] [rfc6749-5.2-a]",
			async () => {
				const subject = await tokensFor("keeper");
				const token = subject.access_token;
				// Where the issuer is named, it is one the issuer added, never the grant's.
				const claims = claimsOf(token);
				if ([claims.aud].flat().includes(issuer))
					expect(claims).toMatchObject({ aud: [api, issuer], aud_added: 1 });
				expect(refusal(await exchange("keeper", token, { audience: issuer }))).toEqual([
					400,
					"invalid_target",
				]);
				expect((await exchange("keeper", token, { audience: api })).status).toBe(200);
			},
		);

		it("issues access tokens only [rfc8693-2.2.2-a] [rfc8693-2.2.2-b] [rfc6749-5.2-a]", async () => {
			const { access_token: token } = await own("gateway");
			for (const type of ["refresh_token", "id_token"]) {
				const answer = await exchange("gateway", token, {
					requested_token_type: `urn:ietf:params:oauth:token-type:${type}`,
				});
				expect(refusal(answer)).toEqual([400, "invalid_request"]);
			}
		});
	});
});

describe("token exchange of a session's token", () => {
	startedFor(exchangeScene(given));

	it("ends at logout a token issued for a session's token that has no family, and refuses that token after [rfc8693-2.1-g] [rfc8693-2.2.2-a] [rfc8693-2.2.2-b] [rfc6749-5.2-a]", async () => {
		browser.forget();
		const subject = await tokensFor("direct");
		expect(subject).not.toHaveProperty("refresh_token");
		const issued = await exchange("direct", subject.access_token);
		expect(await active(issued.body.access_token, "direct")).toBe(true);
		expect(await browser.logout()).toBe(200);
		expect(await active(issued.body.access_token, "direct")).toBe(false);
		expect(refusal(await exchange("direct", subject.access_token))).toEqual([
			400,
			"invalid_request",
		]);
	});
});

describe("token exchange: a cap below the subject token's life", () => {
	/** Shorter than the new system's access tokens, so the cap, not the subject token, ends an exchanged one. */
	const cap = 120;
	startedFor(exchangeScene({ ...given, sessionless: true, maxLifetimeSeconds: cap }));

	it("cuts a longer expires_in to the cap", async () => {
		const { access_token: token } = await tokensFor();
		const issued = await exchange("gateway", token, { expires_in: "7200" });
		expect(issued.status).toBe(200);
		const claims = claimsOf(issued.body.access_token);
		const lifetime = Number(claims.exp) - Number(claims.iat);
		// Legacy caps every access token alike, the subject's too, so its exchanged one ends a little sooner.
		expect(lifetime).toBeGreaterThan(cap / 2);
		expect(lifetime).toBeLessThanOrEqual(cap);
		expect(Number(issued.body.expires_in)).toBeLessThanOrEqual(cap);
	});
});

describe.runIf(areaTarget().can("store-fault:exchange"))(
	"token exchange: the store failing",
	() => {
		const faulty = faultyTarget(scene);

		it("answers 503 while the store is unreachable, never a refusal, and exchanges after", async () => {
			const at = base;
			base = faulty.base();
			browser.forget();
			try {
				const { access_token: token } = await tokensFor();
				const answer = await faulty.whileDown(() => exchange("gateway", token));
				expect(refusal(answer)).toEqual([503, "temporarily_unavailable"]);
				expect((await exchange("gateway", token)).status).toBe(200);
			} finally {
				base = at;
				browser.forget();
			}
		});
	},
);
