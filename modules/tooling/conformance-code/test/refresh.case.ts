import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, faultyTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CodeScene, codeScene } from "../src/main.ts";
import { backChannel, browserAt } from "../src/testing.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const pair = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const secretOf = (id: string) => `${id}-secret-0123456789abcdef`;
const client = (id: string, grants: string[]): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: secretOf(id),
	grants,
	scopes: ["openid", "read", "write"],
	defaultScopes: ["read"],
	redirectUris: [callback],
	firstParty: true,
	audiences: ["https://api.example"],
});
const fields: CodeScene = {
	issuer,
	keys: {
		signing: {
			kid: "rt",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		client("app", ["authorization_code", "refresh_token"]),
		client("other", ["authorization_code", "refresh_token"]),
		client("coded", ["authorization_code"]),
		{ ...client("resource", []), redirectUris: [] },
	],
	users: [{ identifier: "alice", password: "correct horse battery" }],
	refresh: {},
	introspection: true,
	revocation: true,
};
const scene = codeScene(fields);

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(scene);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

const browser = browserAt(() => base, issuer, {
	username: "alice",
	password: "correct horse battery",
});
async function post(path: string, as: string, form: Record<string, string>) {
	const res = await fetch(`${base}${path}`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ ...form, client_id: as, client_secret: secretOf(as) }),
	});
	const text = await res.text();
	return { status: res.status, body: (text ? JSON.parse(text) : {}) as Record<string, string> };
}
/** Logs in, asks for a code and redeems it, as the given client. */
async function tokensFor(as = "app") {
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
const refresh = (token: string, as = "app", extra: Record<string, string> = {}) =>
	post("/oauth/token", as, { grant_type: "refresh_token", refresh_token: token, ...extra });
/** Asked by the client the token was issued to, which may see it whatever its audience. */
const active = async (token: string) =>
	(await post("/oauth/introspect", "app", { token })).body.active;

describe("refresh: rotation and reuse", () => {
	it("rotates on every use, and a spent token gets nothing", async () => {
		const first = await tokensFor();
		const second = await refresh(first.refresh_token ?? "");
		expect(second.status).toBe(200);
		expect(second.body.refresh_token).toBeTruthy();
		expect(second.body.refresh_token).not.toBe(first.refresh_token);
		expect((await refresh(first.refresh_token ?? "")).body.error).toBe("invalid_grant");
	});

	it("revokes the whole family when a spent token comes again, with the access tokens it issued", async () => {
		const first = await tokensFor();
		const second = await refresh(first.refresh_token ?? "");
		expect(await active(second.body.access_token ?? "")).toBe(true);
		await refresh(first.refresh_token ?? "");
		expect((await refresh(second.body.refresh_token ?? "")).body.error).toBe("invalid_grant");
		expect(await active(second.body.access_token ?? "")).toBe(false);
	});

	it("lets at most one of two concurrent uses through, and neither line goes on after", async () => {
		const { refresh_token: token = "" } = await tokensFor();
		const answers = await Promise.all([refresh(token), refresh(token)]);
		expect(answers.filter((a) => a.status === 200).length).toBeLessThanOrEqual(1);
		for (const answer of answers) {
			if (answer.status !== 200) {
				expect(answer.body.error).toBe("invalid_grant");
				continue;
			}
			expect((await refresh(answer.body.refresh_token ?? "")).body.error).toBe("invalid_grant");
		}
	});
});

describe("refresh: what a token may do", () => {
	it("narrows the scope on request and never widens it [rfc6749-6-a]", async () => {
		const { refresh_token: token = "" } = await tokensFor();
		const narrowed = await refresh(token, "app", { scope: "read" });
		expect([narrowed.status, narrowed.body.scope]).toEqual([200, "read"]);
		const widened = await refresh(narrowed.body.refresh_token ?? "", "app", {
			scope: "read admin",
		});
		expect(widened.body.error).toBe("invalid_scope");
	});

	it("refuses another client [rfc6749-6-c] [rfc6749-10.4-b] [rfc6749-10.4-c] [oidc-core-12.1-c]", async () => {
		const { refresh_token: token = "" } = await tokensFor();
		expect((await refresh(token, "other")).body.error).toBe("invalid_grant");
	});

	it("stops working after logout", async () => {
		const { refresh_token: token = "" } = await tokensFor();
		expect(await browser.logout()).toBe(200);
		expect((await refresh(token)).body.error).toBe("invalid_grant");
	});
});

describe("refresh: revocation and introspection", () => {
	it("revokes the family when the issuing client revokes a refresh token, and nobody else can [rfc7009-2-a] [rfc7009-2.1-c]", async () => {
		const first = await tokensFor();
		const second = await refresh(first.refresh_token ?? "");
		const token = second.body.refresh_token ?? "";
		expect((await post("/oauth/revoke", "other", { token })).status).toBe(200);
		const third = await refresh(token);
		expect(third.status).toBe(200);
		const revoked = await post("/oauth/revoke", "app", {
			token: third.body.refresh_token ?? "",
			token_type_hint: "refresh_token",
		});
		expect(revoked.status).toBe(200);
		expect((await refresh(third.body.refresh_token ?? "")).body.error).toBe("invalid_grant");
		expect(await active(third.body.access_token ?? "")).toBe(false);
	});

	it("answers introspection of a refresh token as not active [rfc7662-2.2-a] [rfc7662-2.2-b] [rfc7662-2.2-c]", async () => {
		const { refresh_token: token = "" } = await tokensFor();
		expect((await post("/oauth/introspect", "resource", { token })).body).toEqual({
			active: false,
		});
	});
});

describe.runIf(!areaTarget().differs("refresh-narrowed-scope-persists"))(
	"refresh: narrowing",
	() => {
		it("narrows only the access token it asks for, and the family keeps the original grant [rfc6749-6-e]", async () => {
			const { refresh_token: token = "" } = await tokensFor();
			const narrowed = await refresh(token, "app", { scope: "read" });
			expect([narrowed.status, narrowed.body.scope]).toEqual([200, "read"]);
			const back = await refresh(narrowed.body.refresh_token ?? "");
			expect([back.status, back.body.scope]).toEqual([200, "openid read write"]);
		});
	},
);

describe.runIf(!areaTarget().differs("refresh-without-allowance"))("refresh: who gets one", () => {
	it("gives a refresh token only to a client allowed the refresh grant", async () => {
		expect(await tokensFor("coded")).not.toHaveProperty("refresh_token");
	});
});

describe("refresh: the family's lifetime", () => {
	let short: Started;
	beforeAll(async () => {
		short = await areaTarget().start(codeScene({ ...fields, refresh: { lifetimeSeconds: 3 } }));
		if (short.kind !== "running") throw new Error(`refused:\n${short.output}`);
	});
	afterAll(async () => {
		if (short?.kind === "running") await short.stop();
	});

	it("never extends, however often the token rotates", async () => {
		const at = base;
		base = short.kind === "running" ? short.baseUrl : "";
		browser.forget();
		try {
			let { refresh_token: token = "" } = await tokensFor();
			for (let i = 0; i < 4; i++) {
				await new Promise((resolve) => setTimeout(resolve, 800));
				const rotated = await refresh(token);
				if (rotated.status !== 200) break;
				token = rotated.body.refresh_token ?? "";
			}
			await new Promise((resolve) => setTimeout(resolve, 800));
			expect((await refresh(token)).body.error).toBe("invalid_grant");
		} finally {
			base = at;
			browser.forget();
		}
	});
});

describe.runIf(areaTarget().can("store-fault:refresh-families"))(
	"refresh: the store failing",
	() => {
		const faulty = faultyTarget(scene);

		it("answers 503 while the store is unreachable, never a refusal, and the token works after", async () => {
			const at = base;
			base = faulty.base();
			browser.forget();
			try {
				const { refresh_token: token = "" } = await tokensFor();
				const answer = await faulty.whileDown(() => refresh(token));
				expect([answer.status, answer.body.error]).toEqual([503, "temporarily_unavailable"]);
				// The store answers PING before the app's first read after it is back, so ask again: a 503 whose read
				// failed spends nothing; one whose rotation landed unheard is answered as a reuse, which this does not wait out.
				const until = Date.now() + 10_000;
				let after = await refresh(token);
				while (after.status === 503 && Date.now() < until) {
					await new Promise((resolve) => setTimeout(resolve, 250));
					after = await refresh(token);
				}
				expect(after.status).toBe(200);
			} finally {
				base = at;
				browser.forget();
			}
		});
	},
);
