import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { type Instance, instanceOf, ready, successes } from "@mod/conformance/testing";
import type { ClientScene } from "@mod/conformance-oauth";
import { exportJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { faultScene, issuer, on } from "../../faults/test/faults.ts";
import { proofSpent, proofsCounted } from "../../faults/test/wire.ts";
import { backChannel, succeeded } from "../../testing.ts";

const holder = generateKeyPairSync("ed25519");
const second = generateKeyPairSync("ed25519");
const stranger = generateKeyPairSync("ed25519");
const svc: ClientScene = {
	id: "svc",
	kind: "confidential",
	method: "client_secret_post",
	secret: "svc-secret-0123456789abcdef",
	grants: ["client_credentials"],
	scopes: ["openid"],
	defaultScopes: ["openid"],
};
const scene = faultScene({ clients: [svc], users: [], dpop: true, userinfo: true });
const path = "/oauth/userinfo";
/** `dpop`'s default count of one subject's proofs in a window. */
const proofs = 60;

/** A proof by `key`, for `token` where given, its `iat` that many seconds ahead. */
async function proof(key: typeof holder, htm: string, at: string, token?: string, ahead = 0) {
	const ath = token && createHash("sha256").update(token).digest("base64url");
	return new SignJWT({
		htm,
		htu: `${issuer}${at}`,
		iat: Math.floor(Date.now() / 1000) + ahead,
		jti: randomUUID(),
		...(ath ? { ath } : {}),
	})
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk: await exportJWK(key.publicKey) })
		.sign(key.privateKey);
}

/** A token bound to `key`, by the client's own credentials, so its subject is the client. */
async function boundToken(i: Instance, key = holder) {
	const res = await fetch(`${i.baseUrl}/oauth/token`, {
		method: "POST",
		headers: {
			...backChannel,
			"content-type": "application/x-www-form-urlencoded",
			dpop: await proof(key, "POST", "/oauth/token"),
		},
		body: new URLSearchParams({
			grant_type: "client_credentials",
			client_id: svc.id,
			client_secret: svc.secret ?? "",
		}),
	});
	return (
		((await succeeded(res, "the token endpoint")) as Record<string, string>).access_token ?? ""
	);
}

/** Userinfo's answer to the token and proof, from `source`. */
async function userinfo(i: Instance, token: string, dpop: string, source = "198.51.100.21") {
	const res = await fetch(`${i.baseUrl}${path}`, {
		headers: { ...backChannel, "x-forwarded-for": source, authorization: `DPoP ${token}`, dpop },
	});
	const text = await res.text();
	return {
		status: res.status,
		error: (text ? (JSON.parse(text) as Record<string, unknown>) : {}).error,
		retryAfter: res.headers.get("retry-after"),
		challenge: res.headers.get("www-authenticate"),
	};
}

describe("userinfo: what a DPoP proof writes", () => {
	it("writes nothing for another key's proof, and bounds a client's tokens under the client from any key and source, a proof over the count usable once the wait is over", async () => {
		await on({ name: "userinfo-proofs-bound", scene }, async (d) => {
			const i = instanceOf(d);
			const token = await boundToken(i);
			const other = await boundToken(i, second);
			const spent = successes(i, proofSpent).length;
			for (const _ of [1, 2, 3]) {
				const dpop = await proof(stranger, "GET", path, token);
				expect(await userinfo(i, token, dpop)).toMatchObject({
					status: 401,
					error: "invalid_token",
				});
			}
			expect(successes(i, proofSpent).length).toBe(spent);
			expect(i.relay.executions(proofsCounted(svc.id))).toEqual([]);
			// Each from a source of its own, so a limit per source would never meet them, and by turns
			// from two keys and tokens of the one client, so a count per key or token would not either.
			for (let n = 1; n <= proofs; n++) {
				const [key, held] = n % 2 ? [holder, token] : [second, other];
				const dpop = await proof(key, "GET", path, held);
				expect((await userinfo(i, held, dpop, `203.0.113.${n}`)).status, String(n)).toBe(200);
			}
			expect(successes(i, proofSpent).length).toBe(spent + proofs);
			expect(i.relay.executions(proofsCounted(svc.id)).length).toBeGreaterThanOrEqual(proofs);
			// Ahead by half its window, so it still lies within it after the wait.
			const over = await proof(holder, "GET", path, token, 30);
			const refused = await userinfo(i, token, over, "203.0.113.100");
			expect([refused.status, refused.error, refused.challenge]).toEqual([
				429,
				"rate_limited",
				null,
			]);
			expect(refused.retryAfter).toMatch(/^[1-9]\d*$/);
			expect(successes(i, proofSpent).length).toBe(spent + proofs);
			await new Promise((resolve) => setTimeout(resolve, Number(refused.retryAfter) * 1000));
			expect((await userinfo(i, token, over)).status).toBe(200);
			expect(successes(i, proofSpent).length).toBe(spent + proofs + 1);
		});
	});

	it("answers 503 and spends nothing while the subject's count cannot be made", async () => {
		await on({ name: "userinfo-proofs-uncounted", scene }, async (d) => {
			const i = instanceOf(d);
			const token = await boundToken(i);
			const taken = await userinfo(i, token, await proof(holder, "GET", path, token));
			expect(taken.status).toBe(200);
			const spent = successes(i, proofSpent).length;
			const drop = i.relay.dropReplyTo(proofsCounted(svc.id));
			const answer = await userinfo(i, token, await proof(holder, "GET", path, token));
			await drop.first;
			expect([answer.status, answer.error]).toEqual([503, "temporarily_unavailable"]);
			expect(successes(i, proofSpent).length).toBe(spent);
			await ready(i);
			const again = await userinfo(i, token, await proof(holder, "GET", path, token));
			expect(again.status).toBe(200);
		});
	});
});
