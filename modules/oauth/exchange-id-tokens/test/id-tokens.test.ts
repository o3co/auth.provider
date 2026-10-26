import { createHash } from "node:crypto";
import { BootRefused, contract, defineModule } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import type { Binding } from "@mod/sender-binding";
import { revocations } from "@mod/subject-revocation";
import { type ExchangeVerifier, exchangeVerifiers } from "@mod/token-exchange";
import { tokens } from "@mod/tokens";
import { upstreamNames } from "@mod/users";
import { describe, expect, it } from "vitest";
import {
	api,
	apple,
	appleClaims,
	assembly,
	boot,
	clock,
	elliptic,
	failed,
	google,
	googleClaims,
	idTokenType,
	now,
	said,
	serve,
	settings,
	stranger,
} from "./harness.ts";

describe("exchange-id-tokens", () => {
	it("exchanges Apple's and Google's id_tokens for a token of the account users links them to", async () => {
		const s = await serve();
		for (const [client, token] of [
			["ios-app", await apple.sign(appleClaims())],
			["android-app", await google.sign(googleClaims())],
			["android-app", await google.sign(googleClaims({ iss: "accounts.google.com" }))],
			["web-backend", await google.sign(googleClaims({ azp: undefined }))],
			["web-backend", await google.sign(googleClaims({ azp: "srv" }))],
		] as const) {
			const outcome = await s.exchange(client, token);
			if (outcome.kind !== "issued") throw new Error(`${client}: ${said(outcome).join(": ")}`);
			const checked = await s.app.get(tokens).verifyAccess(String(outcome.body.access_token));
			expect(checked).toMatchObject({
				kind: "valid",
				grant: { subject: "acct-1", issuedTo: client, scope: ["read"], audience: [api] },
			});
			if (checked.kind === "valid") expect(checked.expiresAt).toBeLessThanOrEqual(now + 600_000);
		}
	});

	it("answers a foreign token for the one client that takes it, with no scope or audience of its own", async () => {
		const verifiersSeen = contract<readonly ExchangeVerifier[]>("test.verifiers");
		const reader = defineModule({ name: "verifier-reader", takes: [exchangeVerifiers] }, (m) => [
			m.provide(verifiersSeen).by((c) => c.collect(exchangeVerifiers)),
		]);
		const app = await boot(settings, [reader]);
		const verifier = app.get(verifiersSeen).find((v) => v.tokenType === idTokenType);
		const answer = await verifier?.verify(await apple.sign(appleClaims()));
		expect(answer).toEqual({
			kind: "foreign",
			subject: "acct-1",
			issuer: "https://appleid.apple.com",
			expiresAt: expect.any(Number),
			clients: ["ios-app"],
		});
	});

	it("takes an id_token once", async () => {
		const s = await serve();
		const claims = appleClaims();
		expect(said(await s.exchange("ios-app", await apple.sign(claims)))).toEqual(["issued"]);
		const used = ["invalid_request", "subject_token has been used"];
		expect(said(await s.exchange("ios-app", await apple.sign(claims)))).toEqual(used);
	});

	it("leaves an id_token unused when the exchange is refused", async () => {
		const s = await serve();
		const token = await apple.sign(appleClaims());
		expect(said(await s.exchange("web-backend", token))[0]).toBe("invalid_request");
		expect(said(await s.exchange("ios-app", token))).toEqual(["issued"]);
	});

	it("lets only the client whose audience and party it names exchange it [rfc8693-2.1-g] [rfc8693-2.2.2-b]", async () => {
		const s = await serve();
		const notThisClient = ["invalid_request", "subject_token does not name this client"];
		expect(said(await s.exchange("web-backend", await apple.sign(appleClaims())))).toEqual(
			notThisClient,
		);
		for (const claims of [
			appleClaims({ aud: "com.example.other" }),
			googleClaims({ azp: "web" }),
			googleClaims({ aud: "srv", azp: "other-srv" }),
			appleClaims({ aud: ["com.example.ios", "com.example.device"] }),
		]) {
			const signer = claims.iss.includes("apple") ? apple : google;
			const client = claims.iss.includes("apple") ? "ios-app" : "android-app";
			expect(
				said(await s.exchange(client, await signer.sign(claims))),
				JSON.stringify(claims),
			).toEqual(failed);
		}
	});

	it("refuses another issuer, another algorithm, an unknown key, and an id_token without iat, too old or from the future [rfc8693-2.1-g] [rfc8693-2.2.2-b]", async () => {
		const s = await serve();
		for (const token of [
			await apple.sign(appleClaims({ iss: "https://idp.example" })),
			await elliptic.sign(googleClaims()),
			await stranger.sign(googleClaims()),
			await apple.sign(appleClaims({ iat: undefined })),
			await apple.sign(appleClaims({ iat: now / 1000 - 631 })),
			await apple.sign(appleClaims({ iat: now / 1000 + 120 })),
		]) {
			expect(said(await s.exchange("ios-app", token))).toEqual(failed);
		}
		expect(
			said(await s.exchange("ios-app", await apple.sign(appleClaims({ iat: now / 1000 - 620 })))),
		).toEqual(["issued"]);
	});

	it("refuses an upstream subject users links to no one, and an id_token from before the subject's revocation, by the clock skew", async () => {
		const s = await serve();
		expect(
			said(await s.exchange("ios-app", await apple.sign(appleClaims({ sub: "nobody" })))),
		).toEqual(failed);
		clock.at = now + 1000;
		try {
			await s.app.get(revocations).record("acct-1");
			expect(said(await s.exchange("ios-app", await apple.sign(appleClaims())))).toEqual(failed);
			// An issuer whose clock runs ahead within the skew may have issued this before the revocation.
			const within = await apple.sign(appleClaims({ iat: now / 1000 + 2 }));
			clock.at = now + 3000;
			expect(said(await s.exchange("ios-app", within))).toEqual(failed);
			const after = await apple.sign(appleClaims({ iat: now / 1000 + 32 }));
			clock.at = now + 33_000;
			expect(said(await s.exchange("ios-app", after))).toEqual(["issued"]);
		} finally {
			clock.at = now;
		}
	});

	it("lets the public client exchange only when the nonce is the digest of the key it proves by DPoP", async () => {
		const s = await serve();
		const jkt = "thumbprint-of-the-device-key";
		const nonce = createHash("sha256").update(jkt, "ascii").digest("base64url");
		const bound: Binding = { member: "jkt", confirmation: jkt, tokenType: "DPoP" };
		const claims = appleClaims({ aud: "com.example.device", nonce });
		const other = { ...bound, confirmation: "another-key" };
		expect(said(await s.exchange("device", await apple.sign(claims), other))).toEqual([
			"invalid_request",
			"the request does not prove the key the subject token names",
		]);
		const outcome = await s.exchange("device", await apple.sign(claims), bound);
		expect(outcome).toMatchObject({ kind: "issued", body: { token_type: "DPoP" } });
	});

	it("refuses to start with no upstream, two clients taking one pair, an unregistered client, or a key set or issuer of its own", async () => {
		for (const [section, where] of [
			[{}, "exchange-id-tokens"],
			[
				{
					google: {
						clients: {
							"android-app": { audiences: ["srv"] },
							"web-backend": { audiences: ["srv"] },
						},
					},
				},
				"exchange-id-tokens.google.clients.web-backend",
			],
			[
				{ apple: { clients: { unknown: { audiences: ["a"] } } } },
				"exchange-id-tokens.apple.clients.unknown",
			],
			[{ ...settings, "jwks-uri": "https://keys.example" }, "exchange-id-tokens"],
			[{ apple: { ...settings.apple, issuer: "https://idp.example" } }, "exchange-id-tokens.apple"],
		] as const) {
			const error = await boot(section).then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(error, JSON.stringify(section)).toBeInstanceOf(BootRefused);
			expect(
				(error as BootRefused).refusals.map((r) => r.where),
				JSON.stringify(section),
			).toEqual([where]);
		}
	});

	it("names the client that took a pair first by its key path, never as a value", async () => {
		const shared = {
			google: {
				clients: {
					"android-app": { audiences: ["srv"] },
					"web-backend": { audiences: ["srv"] },
				},
			},
		};
		const error = await boot(shared).catch((e: unknown) => e);
		expect((error as BootRefused).refusals).toEqual([
			{
				where: "exchange-id-tokens.google.clients.web-backend",
				reason:
					"takes an (aud, azp) pair that exchange-id-tokens.google.clients.android-app takes too; one app's id_token is one client's",
			},
		]);
	});

	it("tells users each upstream name it takes, with its issuer, so another module's same name refuses boot unless the issuer is the same", async () => {
		const naming = (issuer: string) =>
			defineModule({ name: "federation-like", takes: [] }, (m) => [
				m.contribute(upstreamNames).by(() => ({
					declaredBy: "federation-like",
					names: [{ name: "google", issuer }],
				})),
			]);
		await expect(boot(settings, [naming("https://accounts.google.com")])).resolves.toBeDefined();
		const refused = await boot(settings, [naming("https://idp.example")]).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(refused).toBeInstanceOf(BootRefused);
		// users names the modules that declare the name, never the name or an issuer.
		expect(JSON.stringify((refused as BootRefused).refusals)).toContain("federation-like");
		await expect(
			boot({ google: { ...settings.google, upstream: "work" } }, [naming("https://idp.example")]),
		).resolves.toBeDefined();
	});
});

it("takes all it names, with both kinds taken or one", async () => {
	for (const section of [settings, { apple: settings.apple }]) {
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect(
			(await takesUnused(assembly(section)))["exchange-id-tokens"],
			JSON.stringify(section),
		).toBeUndefined();
	}
});
