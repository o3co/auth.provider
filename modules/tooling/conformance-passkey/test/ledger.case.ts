import { generateKeyPairSync, randomBytes } from "node:crypto";
import { areaTarget, type Fake, fakeHttp, type Scripted, sceneOf } from "@mod/conformance";
import { codeArea } from "@mod/conformance-code";
import { identityArea, revocationWindowMs } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { oauthArea } from "@mod/conformance-oauth";
import { browser, issuer, password, running } from "@mod/conformance-second-factor/testing";
import { usersLedger } from "@mod/ledger-fakes";
import {
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
} from "@mod/webauthn/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { passkeyArea } from "../src/area.ts";

const grantType = "urn:o3co:oauth:grant-type:webauthn";
const signing = generateKeyPairSync("ed25519");
const at = { origin: issuer };
const secret = "app-secret-0123456789abcdef";
const revocationCredential = randomBytes(32).toString("base64url");
const backChannel = {
	"x-forwarded-proto": "https",
	"x-forwarded-for": "198.51.100.41",
	"x-forwarded-host": new URL(issuer).host,
};
const appCredentials = {
	authorization: `Basic ${Buffer.from(`app:${secret}`).toString("base64")}`,
};
const notAccepted = [400, "invalid_grant", "passkey assertion not accepted"];

/** The passkey login at the token endpoint, over a ledger asked by the URLs given. */
const sceneOver = (ledger: {
	readonly verifyUrl: string;
	readonly subjectUrl?: string;
	readonly credential: string;
}) =>
	sceneOf(
		keysArea.part({
			signing: {
				kid: "passkey-ledger",
				alg: "EdDSA",
				privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		}),
		identityArea.part({
			origin: issuer,
			users: [],
			ledger,
			login: { attempts: 100, windowSeconds: 600 },
			revocations: { credential: revocationCredential, sources: ["198.51.100.0/24"] },
		}),
		oauthArea.part({
			issuer,
			clients: [
				{
					id: "app",
					kind: "confidential",
					method: "client_secret_basic",
					secret,
					grants: [grantType, "refresh_token"],
					scopes: ["read"],
				},
			],
		}),
		codeArea.part({ refresh: {} }),
		passkeyArea.part({
			rpId: new URL(issuer).hostname,
			origins: [issuer],
			login: { requests: 1000, windowSeconds: 60 },
		}),
	);

/** The calls of a passkey's owner and the client, to one running target. */
function calls(base: () => string) {
	const answerOf = async (res: Response) => ({
		status: res.status,
		body: (await res.json()) as Record<string, unknown>,
	});
	/** Signs the user in with a password, and registers a passkey with a new authenticator. */
	const register = async (username: string) => {
		const b = browser(base);
		expect((await b.login(username)).status).toBe(200);
		const offered = await b.send("POST", "/oauth/webauthn/registration/options", {}, {}, "json");
		const authenticator = softwareAuthenticator();
		const response = authenticator.create(offered.body as unknown as CreationOptions, at);
		const done = await b.send(
			"POST",
			"/oauth/webauthn/registration/verify",
			{ response },
			{},
			"json",
		);
		expect(done.status).toBe(200);
		return authenticator;
	};
	/** The grant, on a new challenge. */
	const grant = async (authenticator: ReturnType<typeof softwareAuthenticator>) => {
		const asked = await fetch(`${base()}/oauth/webauthn/authentication/options`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/json" },
			body: JSON.stringify({ client_id: "app" }),
		});
		const assertion = authenticator.get((await asked.json()) as RequestOptions, at);
		return answerOf(
			await fetch(`${base()}/oauth/token`, {
				method: "POST",
				headers: { ...backChannel, ...appCredentials, "content-type": "application/json" },
				body: JSON.stringify({ grant_type: grantType, assertion, scope: "read" }),
			}),
		);
	};
	const refresh = async (token: unknown) =>
		answerOf(
			await fetch(`${base()}/oauth/token`, {
				method: "POST",
				headers: {
					...backChannel,
					...appCredentials,
					"content-type": "application/x-www-form-urlencoded",
				},
				body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: String(token) }),
			}),
		);
	const revoke = async (subject: string) =>
		answerOf(
			await fetch(`${base()}/ledger/subject-revocations`, {
				method: "POST",
				headers: {
					"x-forwarded-proto": "https",
					"x-forwarded-for": "198.51.100.30",
					authorization: `Bearer ${revocationCredential}`,
					"content-type": "application/json",
				},
				body: JSON.stringify({ subject }),
			}),
		);
	return { register, grant, refresh, revoke };
}

const refused = (answer: { status: number; body: Record<string, unknown> }) => [
	answer.status,
	answer.body.error,
	answer.body.error_description,
];
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe.runIf(areaTarget().can("passkey-grant-asks-users"))(
	"H. passkey login at the token endpoint: the user ledger",
	() => {
		describe("with a lookup by subject", () => {
			const users = usersLedger([
				{ identifier: "alice", password },
				{ identifier: "bob", password },
			]);
			/** What the ledger answers of a subject's lookup instead of its users, for a scene's while. */
			let instead: Scripted | undefined;
			let ledger: Fake;
			beforeAll(async () => {
				ledger = await fakeHttp((asked) => {
					const urls = users.urls("");
					return (
						(asked.path === urls.subject && instead) || (users.answer(asked) ?? { status: 404 })
					);
				});
			});
			afterAll(async () => ledger?.stop());
			const s = running(() => {
				const urls = users.urls(ledger.base);
				return sceneOver({
					verifyUrl: urls.verify,
					subjectUrl: urls.subject,
					credential: users.credential,
				});
			});
			const c = calls(() => s.at.base);
			const removed = { status: 404, json: { error: "not_found" } };

			it("refuses a subject the ledger no longer knows, alike before and after a revocation with a new challenge, and takes it back once reinstated [rfc6749-5.2-a]", async () => {
				const authenticator = await c.register("alice");
				const before = await c.grant(authenticator);
				expect(before.status).toBe(200);

				instead = removed;
				const gone = await c.grant(authenticator);
				expect(refused(gone)).toEqual(notAccepted);
				expect(gone.body.access_token).toBeUndefined();
				// A family started before the removal goes on: only a revocation or its end stops it.
				const next = await c.refresh(before.body.refresh_token);
				expect(next.status).toBe(200);

				expect((await c.revoke("alice")).status).toBe(200);
				expect((await c.refresh(next.body.refresh_token)).status).toBe(400);
				await wait(revocationWindowMs);
				expect(refused(await c.grant(authenticator))).toEqual(notAccepted);

				instead = undefined;
				expect((await c.grant(authenticator)).status).toBe(200);
			});

			it("answers 503 while the ledger cannot answer, never a refusal, and issues once it does", async () => {
				const authenticator = await c.register("bob");
				instead = { status: 500 };
				const failing = await c.grant(authenticator);
				expect([failing.status, failing.body.error]).toEqual([503, "temporarily_unavailable"]);
				instead = undefined;
				expect((await c.grant(authenticator)).status).toBe(200);
			});
		});

		describe("with no lookup by subject", () => {
			const users = usersLedger([{ identifier: "carol", password }]);
			let ledger: Fake;
			beforeAll(async () => {
				ledger = await fakeHttp((asked) => users.answer(asked) ?? { status: 404 });
			});
			afterAll(async () => ledger?.stop());
			const s = running(() =>
				sceneOver({ verifyUrl: users.urls(ledger.base).verify, credential: users.credential }),
			);
			const c = calls(() => s.at.base);

			it("answers every grant 503, asking the ledger nothing", async () => {
				const authenticator = await c.register("carol");
				const asked = ledger.received.length;
				const answer = await c.grant(authenticator);
				expect([answer.status, answer.body.error]).toEqual([503, "temporarily_unavailable"]);
				expect(ledger.received.length).toBe(asked);
			});
		});
	},
);
