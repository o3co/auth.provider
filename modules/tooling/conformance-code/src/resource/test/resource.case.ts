import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../../main.ts";
import { backChannel, browserAt } from "../../testing.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const [first, second, unlisted] = ["https://a.example", "https://b.example", "https://c.example"];
const pair = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const user = { username: "alice", password: "correct horse battery" };
const client = (id: string, firstParty: boolean): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: `${id}-secret-0123456789abcdef`,
	grants: ["authorization_code", "refresh_token"],
	scopes: ["openid", "read"],
	defaultScopes: ["openid", "read"],
	audiences: [first, second],
	redirectUris: [callback],
	firstParty,
});

/** A target for the scenes of the describe it is called in, the feature composed or not, with its browser. */
function running(resourceIndicators: boolean) {
	let started: Started;
	const at = { base: "" };
	const browser = browserAt(() => at.base, issuer, user);
	beforeAll(async () => {
		started = await areaTarget().start(
			codeScene({
				issuer,
				keys: {
					signing: {
						kid: "rs",
						alg: "EdDSA",
						privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
						publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
					},
				},
				clients: [client("app", true), client("third", false)],
				users: [{ identifier: user.username, password: user.password }],
				refresh: {},
				...(resourceIndicators
					? { resourceIndicators: true }
					: { without: ["@mod/resource-indicators"] }),
			}),
		);
		if (started.kind !== "running") throw new Error(`refused:\n${started.output}`);
		at.base = started.baseUrl;
	});
	afterAll(async () => {
		if (started?.kind === "running") await started.stop();
	});
	const authorize = (extra: Record<string, string>, as = "app", withSession = true) =>
		browser.authorize(
			{
				response_type: "code",
				client_id: as,
				redirect_uri: callback,
				state: "s1",
				scope: "openid read",
				code_challenge: challenge,
				code_challenge_method: "S256",
				...extra,
			},
			withSession,
		);
	/** A token request by the app; the audience of the access token it gets, if any. */
	const token = async (form: Record<string, string>) => {
		const res = await fetch(`${at.base}/oauth/token`, {
			method: "POST",
			headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				client_id: "app",
				client_secret: "app-secret-0123456789abcdef",
				...form,
			}),
		});
		const body = (await res.json()) as Record<string, string>;
		const claims = body.access_token
			? JSON.parse(Buffer.from(body.access_token.split(".")[1] ?? "", "base64url").toString())
			: {};
		const aud = claims.aud === undefined ? undefined : [claims.aud].flat();
		return { status: res.status, error: body.error, aud, refresh: body.refresh_token };
	};
	const exchange = (code: string, extra: Record<string, string> = {}) =>
		token({
			grant_type: "authorization_code",
			code,
			redirect_uri: callback,
			code_verifier: verifier,
			...extra,
		});
	const codeOf = async (extra: Record<string, string> = {}) =>
		(await authorize(extra)).at?.searchParams.get("code") ?? "";
	return { authorize, token, exchange, codeOf };
}

describe("RFC 8707: the code flow narrowed to a resource", () => {
	const s = running(true);

	it("issues the code for the resource asked, and the exchange keeps it or asks it again [rfc8707-2-c] [rfc6750-5.3-c] [rfc9700-2.3-b]", async () => {
		expect(await s.exchange(await s.codeOf({ resource: second }))).toMatchObject({ aud: [second] });
		expect(
			await s.exchange(await s.codeOf({ resource: second }), { resource: second }),
		).toMatchObject({
			aud: [second],
		});
	});

	it("refuses an exchange asking a resource outside the code's audience", async () => {
		const code = await s.codeOf({ resource: second });
		expect(await s.exchange(code, { resource: first })).toMatchObject({
			status: 400,
			error: "invalid_target",
		});
	});

	it.skipIf(areaTarget().differs("resource-mismatch-keeps-code"))(
		"keeps the code a resource refused, so the right exchange still goes through",
		async () => {
			const code = await s.codeOf({ resource: second });
			await s.exchange(code, { resource: first });
			expect(await s.exchange(code)).toMatchObject({ status: 200, aud: [second] });
		},
	);

	it("answers a resource outside the client's audiences with invalid_target, its state and iss, and no code [rfc6749-4.1.2.1-c] [rfc6749-4.1.2.1-g] [rfc9207-2-a] [oidc-core-3.1.2.6-c] [oidc-core-3.1.2.6-d]", async () => {
		const res = await s.authorize({ resource: unlisted });
		expect([
			`${res.at?.origin}${res.at?.pathname}`,
			res.at?.searchParams.get("error"),
			res.at?.searchParams.get("state"),
			res.at?.searchParams.get("iss"),
			res.at?.searchParams.get("code"),
		]).toEqual([callback, "invalid_target", "s1", issuer, null]);
	});

	it("sends a browser with no session to log in first, and answers consent before the resource [oidc-core-3.1.2.1-k]", async () => {
		const away = await s.authorize({ resource: unlisted }, "app", false);
		expect(away.at?.searchParams.get("error")).toBeNull();
		expect(away.at?.searchParams.get("redirect_to")).toMatch(/oauth\/authorize/);
		const silent = await s.authorize({ resource: unlisted, prompt: "none" }, "third");
		expect(silent.at?.searchParams.get("error")).toBe("consent_required");
	});

	it("narrows a refreshed access token only, refusing one outside the family's audience and keeping the refresh token", async () => {
		// The family's audience named, as the two systems issue a code asking none for different ones.
		const issued = await s.exchange(await s.codeOf({ resource: first }));
		expect(issued.aud).toEqual([first]);
		const refreshing = (extra: Record<string, string> = {}) =>
			s.token({ grant_type: "refresh_token", refresh_token: issued.refresh ?? "", ...extra });
		expect(await refreshing({ resource: second })).toMatchObject({
			status: 400,
			error: "invalid_target",
		});
		expect(await refreshing({ resource: first })).toMatchObject({ status: 200, aud: [first] });
	});
});

describe("RFC 8707: off in the code flow unless composed", () => {
	const s = running(false);

	it("reads no resource at authorization [rfc6749-3.1-e] [oidc-core-3.1.2.2-h]", async () => {
		expect(await s.codeOf({ resource: unlisted })).not.toBe("");
	});
});
