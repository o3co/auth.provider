import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Party, sceneOf } from "@mod/conformance";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { secondFactorArea } from "@mod/conformance-second-factor";
import {
	browser,
	issuer,
	letInByRecovery,
	password,
	running,
	totp,
} from "@mod/conformance-second-factor/testing";
import {
	type Client,
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
} from "@mod/webauthn/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { witnessLedger } from "../src/ledger.ts";
import { type PasskeyPart, passkeyArea } from "../src/main.ts";

const pair = generateKeyPairSync("ed25519");
const rpId = new URL(issuer).hostname;
const at: Client = { origin: issuer };
const users = ["alice", "bob", "carol", "dave", "erin", "frank", "gus"];

const sceneWith = (session: NonNullable<PasskeyPart["session"]>) =>
	sceneOf(
		keysArea.part({
			signing: {
				kid: "passkey-session",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		}),
		identityArea.part({
			origin: issuer,
			users: users.map((identifier) => ({ identifier, password })),
			login: { attempts: 100, windowSeconds: 600 },
		}),
		secondFactorArea.part({ mode: "optional" }),
		passkeyArea.part({ rpId, origins: [issuer], session }),
	);

type Browser = ReturnType<typeof browser>;
type Authenticator = ReturnType<typeof softwareAuthenticator>;

/** POSTs `body` as JSON, the way the passkey routes take it. */
const postJson = (b: Browser, path: string, body: Record<string, unknown> = {}) =>
	b.send("POST", path, body, {}, "json");

/** Registers a passkey from the browser's session; the authenticator keeping it. */
async function registerFrom(b: Browser, authenticator = softwareAuthenticator()) {
	const offered = await postJson(b, "/oauth/webauthn/registration/options");
	expect(offered.status, "the creation options").toBe(200);
	const response = authenticator.create(offered.body as unknown as CreationOptions, at);
	const done = await postJson(b, "/oauth/webauthn/registration/verify", { response });
	expect(done.status, "the registration").toBe(200);
	return authenticator;
}

/** The request options a browser asks, through its own cookies. */
const optionsFor = async (b: Browser) => {
	const asked = await postJson(b, "/session/login/passkey/options");
	expect(asked.status, "the request options").toBe(200);
	return asked.body as unknown as RequestOptions;
};

/** A passkey login in the browser with the authenticator: options, then the assertion. */
const passkeyLogin = async (b: Browser, authenticator: Authenticator) => {
	const response = authenticator.get(await optionsFor(b), at);
	return { response, answer: await postJson(b, "/session/login/passkey", { response }) };
};

const failed = { status: 401, body: { error: "passkey_login_failed" } };

describe.runIf(areaTarget().can("passkey-session-login"))("a passkey login into a session", () => {
	const s = running(sceneWith({}));
	const fresh = () => browser(() => s.at.base);
	/** Signs `username` in by password and registers a passkey from that session. */
	const holding = async (username: string) => {
		const b = fresh();
		expect((await b.login(username)).status).toBe(200);
		return registerFrom(b);
	};

	it("opens a session for the passkey's user, which the session's routes then take", async () => {
		const key = await holding("alice");
		const b = fresh();
		const { answer } = await passkeyLogin(b, key);
		expect(answer).toEqual({ status: 200, body: {} });
		// The session it opened is one the registration routes take.
		expect((await postJson(b, "/oauth/webauthn/registration/options")).status).toBe(200);
	});

	it("refuses alike an assertion from another browser's options, one sent twice, and a credential it does not keep", async () => {
		const key = await holding("bob");
		// The options another browser asked: its requester cookie is not this browser's.
		const other = fresh();
		const elsewhere = key.get(await optionsFor(other), at);
		expect(await postJson(fresh(), "/session/login/passkey", { response: elsewhere })).toEqual(
			failed,
		);
		const b = fresh();
		const { response, answer } = await passkeyLogin(b, key);
		expect(answer.status).toBe(200);
		const again = fresh();
		await optionsFor(again);
		expect(await postJson(again, "/session/login/passkey", { response })).toEqual(failed);
		// A credential no one registered, answering the browser's own options.
		const stranger = softwareAuthenticator();
		const user = { id: Buffer.from("nobody").toString("base64url") };
		stranger.create(
			{
				rp: { id: rpId },
				user,
				challenge: Buffer.from("x".repeat(32)).toString("base64url"),
				pubKeyCredParams: [{ alg: -7, type: "public-key" }],
				authenticatorSelection: { residentKey: "required" },
			} as unknown as CreationOptions,
			at,
		);
		expect((await passkeyLogin(fresh(), stranger)).answer).toEqual(failed);
	});

	it("opens without asking the second factor of a user holding TOTP, the passkey verifying the user", async () => {
		const { secret } = await s.enrol("carol");
		// A session the second factor let in, to register from.
		const b = fresh();
		const held = await b.login("carol");
		const transaction = String(held.body.transaction);
		const factor = (await b.factors(transaction)).find((f) => f.kind === "totp");
		const verified = await b.send("POST", "/session/mfa/verify", {
			transaction_id: transaction,
			factor_id: factor?.id ?? "",
			proof: totp(secret, 1),
		});
		expect(verified.status).toBe(200);
		const key = await registerFrom(b);
		const { answer } = await passkeyLogin(fresh(), key);
		expect(answer).toEqual({ status: 200, body: {} });
	});

	it("checks the request's origin on both routes", async () => {
		for (const path of ["/session/login/passkey/options", "/session/login/passkey"]) {
			const answered = await fresh().send(
				"POST",
				path,
				{},
				{ origin: "https://elsewhere.example" },
				"json",
			);
			expect(answered.status, path).toBe(403);
		}
	});
});

describe.runIf(areaTarget().can("passkey-session-login"))(
	"a passkey login whose verified user does not count as a second factor",
	() => {
		const s = running(sceneWith({ countsAsMfa: false }));
		it("is held by the second factor of a user holding TOTP", async () => {
			const { secret } = await s.enrol("dave");
			const b = browser(() => s.at.base);
			const held = await b.login("dave");
			const transaction = String(held.body.transaction);
			const factor = (await b.factors(transaction)).find((f) => f.kind === "totp");
			await b.send("POST", "/session/mfa/verify", {
				transaction_id: transaction,
				factor_id: factor?.id ?? "",
				proof: totp(secret, 1),
			});
			const key = await registerFrom(b);
			const { answer } = await passkeyLogin(
				browser(() => s.at.base),
				key,
			);
			expect(answer.status).toBe(403);
			expect(answer.body.transaction).toEqual(expect.any(String));
		});
	},
);

describe.runIf(areaTarget().can("passkey-session-login"))(
	"password logins of a subject holding a passkey, refused where the operator says so",
	() => {
		// The passkey witness refusing a password needs, at a ledger the scene runs.
		let ledger: Party | undefined;
		beforeAll(async () => {
			ledger = await witnessLedger();
		});
		afterAll(async () => ledger?.stop());
		const s = running(() =>
			sceneWith({
				password: "refused-when-held",
				...(ledger ? { witness: ledger.config["passkey-witness-http"] } : {}),
			}),
		);
		const fresh = () => browser(() => s.at.base);

		it("refuses the password of a subject holding a passkey as a wrong one, and lets another's in", async () => {
			const b = fresh();
			expect((await b.login("erin")).status).toBe(200);
			await registerFrom(b);
			expect(await fresh().login("erin")).toEqual({
				status: 401,
				body: { error: "invalid_credentials" },
			});
			expect((await fresh().login("gus")).status).toBe(200);
		});

		it("refuses it before the second factor holds the login, and again when a held login resumes", async () => {
			const { secret, codes } = await s.enrol("frank");
			// Held by TOTP while frank holds no passkey yet.
			const waiting = fresh();
			const held = await waiting.login("frank");
			expect(held.status).toBe(403);
			const transaction = String(held.body.transaction);
			// Another login let in by a recovery code, its TOTP step left for the held one, registers a passkey.
			const kept = fresh();
			const other = await kept.login("frank");
			const letIn = await letInByRecovery(kept, String(other.body.transaction), codes[0] ?? "");
			expect(letIn.status).toBe(200);
			await registerFrom(kept);
			// The held login resumes past TOTP: refused, as frank now holds a passkey.
			const factor = (await waiting.factors(transaction)).find((f) => f.kind === "totp");
			const resumed = await waiting.send("POST", "/session/mfa/verify", {
				transaction_id: transaction,
				factor_id: factor?.id ?? "",
				proof: totp(secret, 1),
			});
			expect(resumed.status).toBe(403);
			// A new password login is refused before TOTP holds it.
			expect(await fresh().login("frank")).toEqual({
				status: 401,
				body: { error: "invalid_credentials" },
			});
		});
	},
);

describe.runIf(areaTarget().can("passkey-session-login"))(
	"a passkey login's limit per source",
	() => {
		const s = running(sceneWith({ attempts: 2, windowSeconds: 600 }));
		it("answers too many requests past the options' limit", async () => {
			const b = browser(() => s.at.base);
			await optionsFor(b);
			await optionsFor(b);
			expect((await postJson(b, "/session/login/passkey/options")).status).toBe(429);
		});
	},
);
