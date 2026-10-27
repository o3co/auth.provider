import { generateKeyPairSync, randomUUID } from "node:crypto";
import { type AreaScene, areaTarget, faultyTarget, sceneOf } from "@mod/conformance";
import { codeArea } from "@mod/conformance-code";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { type ClientScene, oauthArea } from "@mod/conformance-oauth";
import { browser, issuer, password, running } from "@mod/conformance-second-factor/testing";
import {
	type Client,
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
	type Twist,
} from "@mod/webauthn/testing";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { passkeyArea } from "../src/main.ts";

const grantType = "urn:o3co:oauth:grant-type:webauthn";
const signing = generateKeyPairSync("ed25519");
const at: Client = { origin: issuer };
const secretOf = (id: string) => `${id}-secret-0123456789abcdef`;
/** What the deployment's proxy adds to a client's own call. */
const backChannel = {
	"x-forwarded-proto": "https",
	"x-forwarded-for": "198.51.100.41",
	"x-forwarded-host": new URL(issuer).host,
};

const confidential = (id: string, grants: string[]): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_basic",
	secret: secretOf(id),
	grants,
	scopes: ["read", "write"],
});
const publicClient = (id: string, grants: string[]): ClientScene => ({
	id,
	kind: "public",
	method: "none",
	grants,
	scopes: ["read"],
});

function sceneFor(users: string[], login: { requests: number; windowSeconds: number }): AreaScene {
	return sceneOf(
		keysArea.part({
			signing: {
				kid: "login",
				alg: "EdDSA",
				privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		}),
		identityArea.part({
			origin: issuer,
			users: users.map((identifier) => ({ identifier, password })),
			login: { attempts: 100, windowSeconds: 600 },
		}),
		oauthArea.part({
			issuer,
			clients: [
				confidential("app", [grantType, "refresh_token"]),
				// Allowed no grant, so not this one, and the scene needs no other grant composed.
				confidential("other", []),
				publicClient("web", [grantType]),
				publicClient("spa", [grantType, "refresh_token"]),
			],
			introspection: true,
			revocation: true,
			dpop: true,
		}),
		codeArea.part({ refresh: {} }),
		passkeyArea.part({ rpId: new URL(issuer).hostname, origins: [issuer], login }),
	);
}

type Answer = { status: number; body: Record<string, unknown> };
/** A client as it authenticates: Basic for a confidential one, its id in the body for a public one. */
const credentials = (as: string): { headers: Record<string, string>; body: object } =>
	as === "web" || as === "spa"
		? { headers: {}, body: { client_id: as } }
		: {
				headers: {
					authorization: `Basic ${Buffer.from(`${as}:${secretOf(as)}`).toString("base64")}`,
				},
				body: {},
			};
const claimsOf = (jwt: unknown) =>
	JSON.parse(Buffer.from(String(jwt).split(".")[1] ?? "", "base64url").toString()) as Record<
		string,
		unknown
	>;

/** The calls a passkey's owner and its clients make to one running target. */
function calls(base: () => string) {
	const post = async (
		path: string,
		as: string,
		params: Record<string, unknown>,
		{
			kind = "form",
			headers = {},
		}: { kind?: "json" | "form"; headers?: Record<string, string> } = {},
	): Promise<Answer> => {
		const client = credentials(as);
		const sent = { ...params, ...client.body };
		const res = await fetch(`${base()}${path}`, {
			method: "POST",
			headers: {
				...backChannel,
				...client.headers,
				"content-type": kind === "json" ? "application/json" : "application/x-www-form-urlencoded",
				...headers,
			},
			body:
				kind === "json"
					? JSON.stringify(sent)
					: new URLSearchParams(sent as Record<string, string>),
		});
		const text = await res.text();
		return { status: res.status, body: text ? JSON.parse(text) : {} };
	};
	/** Request options asked for the client `as`, with whatever else the body holds. */
	const options = async (as = "app", extra: Record<string, unknown> = {}) => {
		const res = await fetch(`${base()}/oauth/webauthn/authentication/options`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/json" },
			body: JSON.stringify({ ...extra, client_id: as }),
		});
		return { status: res.status, body: (await res.json().catch(() => ({}))) as RequestOptions };
	};
	/** Signs `username` in with a password, and registers a passkey with a new authenticator. */
	const register = async (username: string) => {
		const b = browser(base);
		expect((await b.login(username)).status).toBe(200);
		const offered = (await b.send("POST", "/oauth/webauthn/registration/options", {}, {}, "json"))
			.body as unknown as CreationOptions;
		const authenticator = softwareAuthenticator();
		const response = authenticator.create(offered, at);
		const verified = await b.send(
			"POST",
			"/oauth/webauthn/registration/verify",
			{ response },
			{},
			"json",
		);
		expect(verified.status).toBe(200);
		return { authenticator, handle: offered.user.id, id: response.id };
	};
	/** A fresh assertion by the authenticator, for options the client `as` asked just now. */
	const assertion = async (
		authenticator: ReturnType<typeof softwareAuthenticator>,
		as = "app",
		twist: Twist = {},
	) => authenticator.get((await options(as)).body, at, twist);
	const login = (
		as: string,
		sent: unknown,
		extra: Record<string, unknown> = {},
		headers: Record<string, string> = {},
	) =>
		post(
			"/oauth/token",
			as,
			{ grant_type: grantType, assertion: sent, scope: "read", ...extra },
			{ kind: "json", headers },
		);
	return { post, options, register, assertion, login };
}

describe("H. passkey login at the token endpoint", () => {
	const s = running(
		sceneFor(["alice", "bob", "carol", "dave"], { requests: 1000, windowSeconds: 60 }),
	);
	const c = calls(() => s.at.base);

	it("gives the client its tokens for a registered passkey, with a passkey's amr and login time that a refresh keeps, and lets the client revoke [rfc6749-5.1-a] [rfc7009-2-b] [rfc7662-2.2-a] [rfc7662-2.2-b] [rfc7662-2.2-c] [rfc7662-4-d]", async () => {
		const { authenticator } = await c.register("alice");
		const first = await c.login("app", await c.assertion(authenticator), { scope: "read write" });
		expect(first.status).toBe(200);
		expect(first.body).toMatchObject({ token_type: "Bearer", scope: "read write" });
		const claims = claimsOf(first.body.access_token);
		expect(claims).toMatchObject({ client_id: "app" });
		// Ours proves possession alone, `pop`; the legacy build proves `hwk`.
		expect(claims.amr).toEqual(areaTarget().differs("passkey-amr-pop") ? ["hwk"] : ["pop"]);
		expect(typeof claims.auth_time).toBe("number");
		const next = await c.post("/oauth/token", "app", {
			grant_type: "refresh_token",
			refresh_token: String(first.body.refresh_token),
		});
		expect(next.status).toBe(200);
		expect(claimsOf(next.body.access_token)).toMatchObject({
			amr: claims.amr,
			auth_time: claims.auth_time,
		});
		const token = String(next.body.access_token);
		expect((await c.post("/oauth/revoke", "app", { token })).status).toBe(200);
		expect((await c.post("/oauth/introspect", "app", { token })).body).toEqual({ active: false });
	});

	it("gives a public client its access token by the client_id in the JSON body, and no refresh token unless it may refresh", async () => {
		const { authenticator } = await c.register("bob");
		const answer = await c.login("web", await c.assertion(authenticator, "web"));
		expect(answer.status).toBe(200);
		expect(claimsOf(answer.body.access_token)).toMatchObject({ client_id: "web" });
		expect(answer.body.refresh_token).toBeUndefined();
	});

	it("refuses a client not allowed the grant, and a form body [rfc6749-5.2-a]", async () => {
		const { authenticator } = await c.register("carol");
		const other = await c.login("other", await c.assertion(authenticator, "other"));
		expect([other.status, other.body.error]).toEqual([400, "unauthorized_client"]);
		const assertion = await c.assertion(authenticator);
		const form = await c.post("/oauth/token", "app", {
			grant_type: grantType,
			assertion: JSON.stringify(assertion),
		});
		expect(form.status).toBe(400);
		expect((await c.login("app", assertion)).status).toBe(200);
	});

	it("refuses the same assertion twice, and a count that goes back [rfc6749-5.2-a]", async () => {
		const { authenticator } = await c.register("dave");
		const assertion = await c.assertion(authenticator);
		expect((await c.login("app", assertion)).status).toBe(200);
		const again = await c.login("app", assertion);
		expect([again.status, again.body.error]).toEqual([400, "invalid_grant"]);
		const back = await c.login("app", await c.assertion(authenticator, "app", { counter: 0 }));
		expect([back.status, back.body.error]).toEqual([400, "invalid_grant"]);
	});
});

describe("H. passkey login: who the assertion names", () => {
	const s = running(sceneFor(["erin", "fay", "gus", "hal"], { requests: 1000, windowSeconds: 60 }));
	const c = calls(() => s.at.base);

	it("refuses an assertion naming another account's user handle, issuing for neither; its own handle passes [rfc6749-5.2-a]", async () => {
		const owner = await c.register("erin");
		const other = await c.register("fay");
		const crossed = await c.login(
			"app",
			await c.assertion(owner.authenticator, "app", { userHandle: other.handle }),
		);
		expect([crossed.status, crossed.body.error]).toEqual([400, "invalid_grant"]);
		expect(crossed.body.access_token).toBeUndefined();
		const own = await c.login("app", await c.assertion(owner.authenticator));
		expect(own.status).toBe(200);
	});

	it("refuses an assertion without a user handle, and leaves its challenge for the right one [rfc6749-5.2-a]", async () => {
		const { authenticator } = await c.register("gus");
		const offered = (await c.options()).body;
		const bare = await c.login("app", authenticator.get(offered, at, { userHandle: null }));
		expect([bare.status, bare.body.error]).toEqual([400, "invalid_grant"]);
		expect((await c.login("app", authenticator.get(offered, at))).status).toBe(200);
	});

	it.skipIf(areaTarget().differs("passkey-challenge-bound-to-client"))(
		"refuses an assertion answering options another client asked for; the client's own passes",
		async () => {
			const { authenticator } = await c.register("hal");
			const crossed = await c.login("app", await c.assertion(authenticator, "web"));
			expect([crossed.status, crossed.body.error]).toEqual([400, "invalid_grant"]);
			expect(crossed.body.access_token).toBeUndefined();
			expect((await c.login("app", await c.assertion(authenticator, "app"))).status).toBe(200);
		},
	);

	it("answers the same options for anyone, listing no credential", async () => {
		const answers = [
			await c.options(),
			await c.options("web"),
			await c.options("app", { username: "erin" }),
			await c.options("app", { username: "nobody" }),
			await c.options("app", { userId: "erin" }),
		];
		for (const answer of answers) {
			expect(answer.status).toBe(200);
			expect(answer.body.allowCredentials ?? []).toEqual([]);
			expect(Object.keys(answer.body).sort()).toEqual(Object.keys(answers[0]?.body ?? {}).sort());
		}
	});

	it("binds the token to the key a DPoP proof shows [rfc9449-5-b] [rfc9449-6.1-a]", async () => {
		const { authenticator } = await c.register("gus");
		const holder = generateKeyPairSync("ed25519");
		const proof = await new SignJWT({
			htm: "POST",
			htu: `${issuer}/oauth/token`,
			iat: Math.floor(Date.now() / 1000),
			jti: randomUUID(),
		})
			.setProtectedHeader({
				alg: "EdDSA",
				typ: "dpop+jwt",
				jwk: await exportJWK(holder.publicKey),
			})
			.sign(holder.privateKey);
		const answer = await c.login(
			"spa",
			await c.assertion(authenticator, "spa"),
			{},
			{ dpop: proof },
		);
		expect(answer.status).toBe(200);
		expect(answer.body.token_type).toBe("DPoP");
		const jkt = await calculateJwkThumbprint(await exportJWK(holder.publicKey), "sha256");
		expect(claimsOf(answer.body.access_token).cnf).toEqual({ jkt });
	});
});

describe("H. passkey login: the options' limit", () => {
	const s = running(sceneFor([], { requests: 3, windowSeconds: 600 }));
	const c = calls(() => s.at.base);

	it("answers 429 once a source has asked for options past the limit [guarantee-10-a]", async () => {
		for (let i = 0; i < 3; i++) expect((await c.options()).status).toBe(200);
		expect((await c.options()).status).toBe(429);
	});
});

describe("H. passkey login: a small options limit", () => {
	const s = running(sceneFor(["ines"], { requests: 2, windowSeconds: 60 }));
	const c = calls(() => s.at.base);
	/** Request options for `app`, asked from the address `from`. */
	const optionsFrom = async (from: string) => {
		const res = await fetch(`${s.at.base}/oauth/webauthn/authentication/options`, {
			method: "POST",
			headers: { ...backChannel, "x-forwarded-for": from, "content-type": "application/json" },
			body: JSON.stringify({ client_id: "app" }),
		});
		const text = await res.text();
		return {
			status: res.status,
			retryAfter: Number(res.headers.get("retry-after")),
			body: (text ? JSON.parse(text) : {}) as Record<string, unknown>,
		};
	};

	it("answers rate_limited with a wait within the window past the limit, to that source's options alone [guarantee-10-a]", async () => {
		const { authenticator } = await c.register("ines");
		for (let i = 0; i < 2; i++)
			expect((await optionsFrom(backChannel["x-forwarded-for"])).status).toBe(200);
		const over = await optionsFrom(backChannel["x-forwarded-for"]);
		expect([over.status, over.body.error]).toEqual([429, "rate_limited"]);
		expect(over.retryAfter).toBeGreaterThanOrEqual(1);
		expect(over.retryAfter).toBeLessThanOrEqual(60);
		// Another source still gets options, and the limited source's grant is not counted with them.
		const elsewhere = await optionsFrom("198.51.100.42");
		expect(elsewhere.status).toBe(200);
		const sent = authenticator.get(elsewhere.body as unknown as RequestOptions, at);
		const login = await c.login("app", sent);
		expect([login.status, typeof login.body.access_token]).toEqual([200, "string"]);
	});
});

describe.runIf(areaTarget().can("store-fault:passkeys"))(
	"H. passkey login: the store failing",
	() => {
		const faulty = faultyTarget(sceneFor(["hana"], { requests: 1000, windowSeconds: 60 }));
		const c = calls(() => faulty.base());

		it("answers 503 to options and to the grant while the store is unreachable, never a refusal", async () => {
			const { authenticator } = await c.register("hana");
			const assertion = await c.assertion(authenticator);
			expect((await faulty.whileDown(() => c.options())).status).toBe(503);
			expect((await faulty.whileDown(() => c.login("app", assertion))).status).toBe(503);
			expect((await c.login("app", assertion)).status).toBe(200);
		});
	},
);
