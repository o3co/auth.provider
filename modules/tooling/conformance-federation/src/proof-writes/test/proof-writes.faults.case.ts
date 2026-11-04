import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { type Instance, instanceOf, on, ready, successes } from "@mod/conformance/testing";
import type { ClientScene } from "@mod/conformance-oauth";
import { decodeJwt, exportJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { browser as openBrowser } from "../../../test/browser.ts";
import { fakeUpstream } from "../../../test/upstream.ts";
import { proofSpent, proofsCounted } from "../../faults/test/wire.ts";
import { federationScene, landedStatus } from "../../main.ts";

const origin = "https://issuer.example";
const landing = "https://app.example/home";
const callback = "https://app.example/cb";
const verifier = "w".repeat(43);
const path = "/oauth/federation/corp/token";
const upstreamClient = { id: "as-client", secret: "as-client-secret-0123456789" };
const pair = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
const stranger = generateKeyPairSync("ed25519");
const app: ClientScene = {
	id: "fed-app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "fed-app-secret-0123456789abcdef",
	grants: ["authorization_code", "refresh_token"],
	scopes: ["openid", "read"],
	defaultScopes: ["read"],
	audiences: ["fed-app"],
	redirectUris: [callback],
	firstParty: true,
	upstreamTokens: { postLogoutRedirectUris: [] },
};
/** `dpop`'s default count of one subject's proofs in a window; the route's own per source is as many. */
const proofs = 60;
/** The subject a token stands for, which its count goes by. */
const subjectOf = (token: string) => decodeJwt(token).sub ?? "";

type Upstream = Awaited<ReturnType<typeof fakeUpstream>>;

/** Upstream tokens kept and handed on the Redis store, to a client whose tokens DPoP binds. */
const sceneAt = (corp: Upstream) => ({
	...federationScene({
		origin,
		keys: {
			signing: {
				kid: "fed",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		idps: [
			{
				name: "corp",
				issuer: corp.issuer,
				clientId: upstreamClient.id,
				clientSecret: upstreamClient.secret,
			},
		],
		landing,
		returnTargets: [],
		users: [
			{
				identifier: "alice",
				password: "correct horse battery",
				upstream: { idp: "corp", subject: "u-alice" },
			},
		],
		clients: [app],
		dpop: true,
		keepsUpstreamTokens: true,
	}),
	storeFaults: true,
});

/** A proof by `key`, for `token` where given, its `iat` that many seconds ahead. */
async function proof(key: typeof holder, at: string, token?: string, ahead = 0) {
	const ath = token && createHash("sha256").update(token).digest("base64url");
	return new SignJWT({
		htm: "POST",
		htu: `${origin}${at}`,
		iat: Math.floor(Date.now() / 1000) + ahead,
		jti: randomUUID(),
		...(ath ? { ath } : {}),
	})
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk: await exportJWK(key.publicKey) })
		.sign(key.privateKey);
}

/** A form posted from `source`, and its answer. */
async function post(
	i: Instance,
	at: string,
	form: Record<string, string>,
	more: Record<string, string>,
	source = "198.51.100.40",
) {
	const res = await fetch(`${i.baseUrl}${at}`, {
		method: "POST",
		redirect: "manual",
		headers: {
			"x-forwarded-proto": "https",
			"x-forwarded-for": source,
			"content-type": "application/x-www-form-urlencoded",
			...more,
		},
		body: new URLSearchParams(form),
	});
	const text = await res.text();
	return {
		status: res.status,
		body: (text.startsWith("{") ? JSON.parse(text) : {}) as Record<string, unknown>,
		retryAfter: res.headers.get("retry-after"),
		challenge: res.headers.get("www-authenticate"),
	};
}

/** A token bound to the holder's key, by the code flow in a session logged in through the upstream. */
async function boundToken(i: Instance, corp: Upstream) {
	const b = openBrowser(() => i.baseUrl, origin);
	const started = await b.get("/session/oauth/federation/corp");
	const query = corp.authorize(started.location, { subject: "u-alice", tokens: {} });
	const done = await b.get(`/session/oauth/federation/corp/callback?${query}`);
	expect([done.status, done.location]).toEqual([landedStatus(), landing]);
	const asked = new URLSearchParams({
		response_type: "code",
		client_id: app.id,
		redirect_uri: callback,
		scope: "openid read",
		state: "s",
		code_challenge: createHash("sha256").update(verifier).digest("base64url"),
		code_challenge_method: "S256",
	});
	const answered = await b.get(`/oauth/authorize?${asked}`);
	const redeemed = await post(
		i,
		"/oauth/token",
		{
			grant_type: "authorization_code",
			code: new URL(answered.location).searchParams.get("code") ?? "",
			redirect_uri: callback,
			code_verifier: verifier,
			client_id: app.id,
			client_secret: app.secret ?? "",
		},
		{ dpop: await proof(holder, "/oauth/token") },
	);
	expect([redeemed.status, redeemed.body.token_type]).toEqual([200, "DPoP"]);
	return redeemed.body.access_token as string;
}

/** The route's answer to the token and proof, from `source`. */
const upstreamToken = (i: Instance, token: string, dpop: string, source?: string) =>
	post(i, path, {}, { authorization: `DPoP ${token}`, dpop }, source);

/** Runs a scene on a deployment of its own, with an upstream started before it and stopped however it ends. */
async function onUpstream(name: string, scene: (i: Instance, corp: Upstream) => Promise<void>) {
	const corp = await fakeUpstream(upstreamClient);
	try {
		await on({ name, scene: sceneAt(corp) }, (d) => scene(instanceOf(d), corp));
	} finally {
		await corp.stop();
	}
}

describe("federation tokens: what a DPoP proof writes", () => {
	it("writes nothing for another key's proof, and bounds the token's subject from any source, its proof over the count usable once the wait is over", async () => {
		await onUpstream("tokens-proofs-bound", async (i, corp) => {
			const token = await boundToken(i, corp);
			const spent = successes(i, proofSpent).length;
			for (const _ of [1, 2, 3]) {
				const refused = await upstreamToken(i, token, await proof(stranger, path, token));
				expect([refused.status, refused.body.error]).toEqual([401, "invalid_token"]);
			}
			expect(successes(i, proofSpent).length).toBe(spent);
			expect(i.relay.executions(proofsCounted(subjectOf(token)))).toEqual([]);
			// Each from a source of its own, so the route's limit per source never meets them.
			for (let n = 1; n <= proofs; n++) {
				const dpop = await proof(holder, path, token);
				const got = await upstreamToken(i, token, dpop, `203.0.113.${n}`);
				expect(got.status, String(n)).toBe(200);
			}
			expect(successes(i, proofSpent).length).toBe(spent + proofs);
			// Ahead by half its window, so it still lies within it after the wait.
			const over = await proof(holder, path, token, 30);
			const refused = await upstreamToken(i, token, over, "203.0.113.100");
			expect([refused.status, refused.body.error, refused.challenge]).toEqual([
				429,
				"rate_limited",
				null,
			]);
			expect(refused.retryAfter).toMatch(/^[1-9]\d*$/);
			expect(successes(i, proofSpent).length).toBe(spent + proofs);
			await new Promise((resolve) => setTimeout(resolve, Number(refused.retryAfter) * 1000));
			expect((await upstreamToken(i, token, over, "203.0.113.101")).status).toBe(200);
			expect(successes(i, proofSpent).length).toBe(spent + proofs + 1);
		});
	});

	it("answers 503 and spends nothing while the subject's count cannot be made", async () => {
		await onUpstream("tokens-proofs-uncounted", async (i, corp) => {
			const token = await boundToken(i, corp);
			const taken = await upstreamToken(i, token, await proof(holder, path, token));
			expect(taken.status).toBe(200);
			const spent = successes(i, proofSpent).length;
			const drop = i.relay.dropReplyTo(proofsCounted(subjectOf(token)));
			const answer = await upstreamToken(i, token, await proof(holder, path, token));
			await drop.first;
			expect([answer.status, answer.body.error]).toEqual([503, "temporarily_unavailable"]);
			expect(successes(i, proofSpent).length).toBe(spent);
			await ready(i);
			const again = await upstreamToken(i, token, await proof(holder, path, token));
			expect(again.status).toBe(200);
		});
	});
});
