import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { idTokenChecks, type UsedIdTokens } from "../src/contract.ts";
import {
	apple,
	appleClaims,
	boot,
	clock,
	google,
	googleClaims,
	now,
	said,
	serve,
	settings,
	stranger,
	usedIn,
} from "./harness.ts";
import { memoryUsedIdTokens } from "./stores.ts";

const minute = 60_000;
const used = ["invalid_request", "subject_token has been used"];
const nameOf = (token: string) =>
	createHash("sha256").update(token.split(".").slice(0, 2).join(".")).digest("base64url");

/** A store that records each lifetime it is asked to keep a name for. */
const recording = () => {
	const kept: number[] = [];
	const memory = memoryUsedIdTokens();
	const store: UsedIdTokens = {
		save: (kind, name, lifetimeMs) => {
			kept.push(lifetimeMs);
			return memory.used.save(kind, name, lifetimeMs);
		},
	};
	return { kept, store };
};

describe("idTokenChecks", () => {
	it("names the issuers it takes, each kind's every `iss`", async () => {
		expect((await boot(settings)).get(idTokenChecks).issuers).toEqual([
			"https://appleid.apple.com",
			"https://accounts.google.com",
			"accounts.google.com",
		]);
		const appleOnly = await boot({ apple: settings.apple });
		expect(appleOnly.get(idTokenChecks).issuers).toEqual(["https://appleid.apple.com"]);
	});

	it("checks an id_token for the account and the one client it is for, as the exchange does", async () => {
		const checks = (await boot(settings)).get(idTokenChecks);
		const claims = appleClaims();
		expect(await checks.check(await apple.sign(claims))).toEqual({
			kind: "taken",
			subject: "acct-1",
			issuer: "https://appleid.apple.com",
			issuedAt: claims.iat * 1000,
			standingAt: claims.iat * 1000 - 30_000,
			expiresAt: claims.exp * 1000,
			client: "ios-app",
		});
		const digest = createHash("sha256").update("a-key", "ascii").digest("base64url");
		expect(await checks.check(await google.sign(googleClaims({ nonce: digest })))).toMatchObject({
			kind: "taken",
			issuer: "https://accounts.google.com",
			client: "android-app",
			holderDigest: digest,
		});
		// A nonce that names no key is no holder's.
		const hex = "0123456789abcdef0123456789abcdef";
		expect(await checks.check(await google.sign(googleClaims({ nonce: hex })))).not.toHaveProperty(
			"holderDigest",
		);
		for (const refused of [
			await stranger.sign(googleClaims()),
			await apple.sign(appleClaims({ iss: "https://idp.example" })),
			await apple.sign(appleClaims({ aud: "com.example.other" })),
			await apple.sign(appleClaims({ sub: "nobody" })),
			await apple.sign(appleClaims({ iat: now / 1000 - 3600 })),
			"no.token",
		]) {
			expect(await checks.check(refused)).toEqual({ kind: "invalid" });
		}
	});

	it("takes an id_token once, by the contract or by the exchange", async () => {
		const s = await serve();
		const checks = s.app.get(idTokenChecks);
		const first = await apple.sign(appleClaims({ sub: "apple-sub" }));
		expect(await checks.consume(first)).toBe("consumed");
		expect(await checks.consume(first)).toBe("replayed");
		expect(said(await s.exchange("ios-app", first))).toEqual(used);
		const second = await apple.sign(appleClaims({ iat: now / 1000 - 20 }));
		expect(said(await s.exchange("ios-app", second))).toEqual(["issued"]);
		expect(await checks.consume(second)).toBe("replayed");
	});

	it("keeps each record until the latest any setting could take the id_token, whatever the section says", async () => {
		const iat = now / 1000 - 10;
		for (const section of [
			settings,
			{ ...settings, "max-age": "1m", "clock-skew": "0s" },
			{ ...settings, "max-age": "1h", "clock-skew": "5m" },
		]) {
			const { kept, store } = recording();
			const checks = (await boot(section, [], usedIn(store))).get(idTokenChecks);
			// Ending before an hour from `iat`: kept to `exp`, the longest skew and a minute.
			await checks.consume(await apple.sign(appleClaims({ iat, exp: iat + 600 })));
			// Ending later: kept to an hour from `iat`, the longest `max-age`, and the same.
			await checks.consume(await apple.sign(appleClaims({ iat, exp: iat + 86_400 })));
			expect(kept, JSON.stringify(section)).toEqual([
				(iat + 600) * 1000 + 6 * minute - now,
				(iat + 3600) * 1000 + 6 * minute - now,
			]);
		}
	});

	describe("widening max-age over records already kept", () => {
		const token = () => apple.sign(appleClaims({ iat: now / 1000 - 10, exp: now / 1000 + 3600 }));
		const later = async (
			memory: ReturnType<typeof memoryUsedIdTokens>,
			run: () => Promise<void>,
		) => {
			memory.advance(30 * minute);
			clock.at = now + 30 * minute;
			try {
				await run();
			} finally {
				clock.at = now;
			}
		};

		it("never takes again an id_token this version kept, though max-age widens from 10m to 1h", async () => {
			const memory = memoryUsedIdTokens();
			const idToken = await token();
			const before = await serve(settings, usedIn(memory.used));
			expect(said(await before.exchange("ios-app", idToken))).toEqual(["issued"]);
			await later(memory, async () => {
				const widened = await serve({ ...settings, "max-age": "1h" }, usedIn(memory.used));
				expect(said(await widened.exchange("ios-app", idToken))).toEqual(used);
			});
		});

		it("takes again one kept as the earlier version kept it, so widening waits for those records to age", async () => {
			const memory = memoryUsedIdTokens();
			const idToken = await token();
			const { iat, exp } = appleClaims({ iat: now / 1000 - 10, exp: now / 1000 + 3600 });
			// The earlier version's record: to `exp` or `iat` and max-age (10m), then the skew (30s) and a minute.
			const earlier = Math.min(exp * 1000, iat * 1000 + 10 * minute) + 30_000 + minute - now;
			await memory.used.save("apple", nameOf(idToken), earlier);
			await later(memory, async () => {
				const widened = await serve({ ...settings, "max-age": "1h" }, usedIn(memory.used));
				expect(said(await widened.exchange("ios-app", idToken))).toEqual(["issued"]);
			});
		});
	});
});
