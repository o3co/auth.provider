import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { areaTarget, auditEvents, type Fake, fakeHttp, type Started } from "@mod/conformance";
import { httpLedger, type UserScene } from "@mod/conformance-identity";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CodeScene, codeScene } from "../../main.ts";
import { backChannel, browserAt } from "../../testing.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const api = "https://api.example";
const password = "correct horse battery";
const pair = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const unverified = "email address is not verified";

const codeClient = (id: string, firstParty: boolean): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: `${id}-secret-0123456789abcdef`,
	grants: ["authorization_code"],
	scopes: ["openid", "read"],
	defaultScopes: ["openid"],
	redirectUris: [callback],
	firstParty,
});
const bff: ClientScene = {
	id: "bff",
	kind: "confidential",
	method: "client_secret_basic",
	secret: "bff-secret-0123456789abcdef",
	grants: ["session"],
	scopes: ["read"],
	defaultScopes: [],
	audiences: [api],
};
/** alice's email is stated verified, bob's stated not, carol's not stated at all. */
const users: UserScene[] = [
	{ identifier: "alice", password, subject: "s-alice", emailVerified: true },
	{ identifier: "bob", password, subject: "s-bob", emailVerified: false },
	{ identifier: "carol", password, subject: "s-carol" },
];
const fields = (extra: Partial<CodeScene>): CodeScene => ({
	issuer,
	keys: {
		signing: {
			kid: "ve",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [codeClient("app", true), codeClient("third", false), bff],
	users,
	sessionGrant: true,
	...extra,
});

function started(scene: () => CodeScene) {
	const at: { running?: Started; base: string } = { base: "" };
	beforeAll(async () => {
		at.running = await areaTarget().start(codeScene(scene()));
		if (at.running.kind !== "running") throw new Error(`refused:\n${at.running.output}`);
		at.base = at.running.baseUrl;
	});
	afterAll(async () => {
		if (at.running?.kind === "running") await at.running.stop();
	});
	return at;
}

/** The calls of one user's browser, and of the clients beside it, to the running target. */
function as(at: { base: string }, username: string) {
	const browser = browserAt(() => at.base, issuer, { username, password });
	const authorize = (extra: Record<string, string> = {}) =>
		browser.authorize({
			response_type: "code",
			client_id: "app",
			redirect_uri: callback,
			state: "s1",
			scope: "openid",
			code_challenge: challenge,
			code_challenge_method: "S256",
			...extra,
		});
	const redeem = async (code: string) => {
		const res = await fetch(`${at.base}/oauth/token`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				client_id: "app",
				client_secret: "app-secret-0123456789abcdef",
				code,
				redirect_uri: callback,
				code_verifier: verifier,
			}),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	const sessionGrant = async () => {
		const cookie = await browser.login();
		const res = await fetch(`${at.base}/oauth/token`, {
			method: "POST",
			headers: browser.headers({
				"content-type": "application/x-www-form-urlencoded",
				cookie,
				origin: issuer,
				authorization: `Basic ${Buffer.from(`bff:${bff.secret}`).toString("base64")}`,
			}),
			body: new URLSearchParams({ grant_type: "session", scope: "read" }),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	return { authorize, redeem, sessionGrant };
}

describe("verified email: the authorization endpoint", () => {
	const at = started(() => fields({ verifiedEmail: true }));

	it("gives a user whose email is stated verified a code that redeems", async () => {
		const answer = await as(at, "alice").authorize();
		const code = answer.at?.searchParams.get("code") ?? "";
		expect(code).not.toBe("");
		expect((await as(at, "alice").redeem(code)).status).toBe(200);
	});

	it.each(["bob", "carol"])(
		"sends %s back with access_denied, the state and the issuer, and no code [rfc6749-4.1.2.1-c] [rfc6749-4.1.2.1-g] [rfc9207-2-a] [oidc-core-3.1.2.6-c] [oidc-core-3.1.2.6-d]",
		async (user) => {
			const answer = await as(at, user).authorize();
			expect(`${answer.at?.origin}${answer.at?.pathname}`).toBe(callback);
			const params = answer.at?.searchParams;
			expect(params?.get("error")).toBe("access_denied");
			expect(params?.get("error_description")).toBe(unverified);
			expect(params?.get("state")).toBe("s1");
			expect(params?.get("iss")).toBe(issuer);
			expect(params?.has("code")).toBe(false);
		},
	);

	it("answers access_denied, not consent_required, without a page to ask on", async () => {
		const answer = await as(at, "bob").authorize({ client_id: "third", prompt: "none" });
		expect(answer.at?.searchParams.get("error")).toBe("access_denied");
	});

	describe.runIf(areaTarget().can(auditEvents.need))("audit events", () => {
		it("records the refusal with the reason email_not_verified", async () => {
			if (at.running?.kind !== "running") throw new Error("not running");
			const { events } = await auditEvents.of(at.running).during(() => as(at, "bob").authorize());
			expect(events.filter((event) => event.kind === "authorize.rejected")).toEqual([
				{
					kind: "authorize.rejected",
					at: expect.any(Number),
					attributes: {
						client: "app",
						reason: "email_not_verified",
						policy: "verified-email",
						source: expect.any(String),
					},
				},
			]);
		});
	});
});

describe("verified email: the session grant", () => {
	const at = started(() => fields({ verifiedEmail: true }));

	it("issues for a user whose email is stated verified", async () => {
		expect((await as(at, "alice").sessionGrant()).status).toBe(200);
	});

	it.each(["bob", "carol"])(
		"refuses %s as invalid_grant, saying why [rfc6749-5.2-a]",
		async (user) => {
			const res = await as(at, user).sessionGrant();
			expect([res.status, res.body.error, res.body.error_description]).toEqual([
				400,
				"invalid_grant",
				unverified,
			]);
			expect(res.body).not.toHaveProperty("access_token");
		},
	);

	it.runIf(areaTarget().can(auditEvents.need))(
		"records the refusal with the policy and its reason",
		async () => {
			if (at.running?.kind !== "running") throw new Error("not running");
			const { events } = await auditEvents
				.of(at.running)
				.during(() => as(at, "bob").sessionGrant());
			expect(events.filter((event) => event.kind === "token.issued.failure")).toEqual([
				{
					kind: "token.issued.failure",
					at: expect.any(Number),
					attributes: expect.objectContaining({
						grant_type: "session",
						reason: "issuance_refused",
						policy: "verified-email",
						refusal: "email_not_verified",
					}),
				},
			]);
		},
	);
});

describe("verified email: off", () => {
	const at = started(() => fields({ without: ["@mod/verified-email"] }));

	it("gives a code to a user whose email is not stated verified", async () => {
		const code = (await as(at, "bob").authorize()).at?.searchParams.get("code") ?? "";
		expect(code).not.toBe("");
		expect((await as(at, "bob").redeem(code)).status).toBe(200);
	});
});

describe.runIf(areaTarget().can(httpLedger))(
	"verified email: users from a ledger over HTTP",
	() => {
		const credential = randomBytes(32).toString("hex");
		let fake: Fake;
		// Started before the target, which asks it at each login: alice's email is verified, bob's not.
		beforeAll(async () => {
			fake = await fakeHttp(async (asked) => {
				if (asked.headers.authorization !== `Bearer ${credential}`) return { status: 401 };
				const { email, password: given } = JSON.parse(asked.body);
				if (given !== password || !["alice", "bob"].includes(email)) return { status: 401 };
				return {
					json: {
						id: `s-${email}`,
						username: email,
						email: `${email}@ledger.example`,
						emailVerified: email === "alice",
					},
				};
			});
		});
		afterAll(async () => {
			await fake?.stop();
		});
		const at = started(() =>
			fields({
				verifiedEmail: true,
				users: [],
				ledger: { verifyUrl: `${fake.base}/ledger/authenticate`, credential },
			}),
		);

		it("tells by what the ledger said at login", async () => {
			const code = (await as(at, "alice").authorize()).at?.searchParams.get("code") ?? "";
			expect((await as(at, "alice").redeem(code)).status).toBe(200);
			expect((await as(at, "alice").sessionGrant()).status).toBe(200);
			const refused = await as(at, "bob").sessionGrant();
			expect([refused.status, refused.body.error]).toEqual([400, "invalid_grant"]);
		});

		it("sends a user the ledger states unverified back with access_denied", async () => {
			const answer = await as(at, "bob").authorize();
			expect(answer.at?.searchParams.get("error")).toBe("access_denied");
		});
	},
);
