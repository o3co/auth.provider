import type { ExternalJwt, Policy, Verified } from "@mod/external-jwt";
import { isUnavailable } from "@mod/kernel";
import { UpstreamRefused } from "@mod/upstreams";
import { describe, expect, it } from "vitest";
import { type IdTokenRules, idTokenReaderOf } from "../src/contract.ts";

describe("upstream-client's id_token reader", () => {
	const now = 1_800_000_000_000;
	const seconds = now / 1000;
	const rules: IdTokenRules = {
		issuer: "https://idp.example",
		client: "cid",
		jwks: { url: "https://idp.example/keys", hosts: ["idp.example"] },
		algorithms: ["RS256"],
		skewMs: 30_000,
		emailVerified: [true],
		what: "idp-x",
	};
	const claims = { iss: rules.issuer, sub: "alice", aud: "cid", iat: seconds, nonce: "n" };
	/** A reader over a stand-in external-jwt that answers `verified` and records what it was asked. */
	const readerOf = (verified: Verified, more: Partial<IdTokenRules> = {}) => {
		const asked: { keys: unknown; policy: Policy }[] = [];
		const jwt: ExternalJwt = {
			algorithms: ["RS256"],
			verifierOf: (keys, policy) => {
				asked.push({ keys, policy });
				return { verify: async () => verified };
			},
		};
		return { read: idTokenReaderOf(jwt, { ...rules, ...more }, { now: () => now }), asked };
	};
	const valid = (more: Record<string, unknown> = {}): Verified => ({
		kind: "valid",
		header: {},
		claims: Object.fromEntries(
			Object.entries({ ...claims, ...more }).filter(([, value]) => value !== undefined),
		),
	});
	const outcome = (run: Promise<unknown>) =>
		run.then(
			(value) => value,
			(error) =>
				error instanceof UpstreamRefused ? "refused" : isUnavailable(error) ? error.what : error,
		);

	it("asks external-jwt for the type's keys, algorithms, issuer and client", () => {
		const { asked } = readerOf(valid());
		expect(asked).toEqual([
			{
				keys: { jwks: rules.jwks },
				policy: {
					algorithms: ["RS256"],
					skewMs: 30_000,
					expect: { iss: rules.issuer, aud: ["cid"] },
				},
			},
		]);
	});

	it("reads the subject, the login time and the claims of an id_token that holds", async () => {
		const { read } = readerOf(valid({ auth_time: seconds - 60, amr: ["pwd"] }));
		expect(await read("t", "n")).toEqual({
			login: { subject: "alice", authenticatedAt: (seconds - 60) * 1000 },
			claims: { ...claims, auth_time: seconds - 60, amr: ["pwd"] },
		});
		const atAllowance = readerOf(valid({ auth_time: seconds + 30 }));
		expect((await atAllowance.read("t", "n")).login.authenticatedAt).toBe(now + 30_000);
		const shared = readerOf(valid({ aud: ["cid", "other"], azp: "cid" }));
		expect((await shared.read("t", "n")).login.subject).toBe("alice");
	});

	it("is unavailable without a key set, naming the type", async () => {
		expect(await outcome(readerOf({ kind: "unavailable" }).read("t", "n"))).toBe("idp-x");
	});

	it("refuses an id_token that does not hold", async () => {
		const cases: Record<string, Verified> = {
			"a reason external-jwt gives": { kind: "invalid", reason: "signature" },
			"no subject": valid({ sub: undefined }),
			"an empty subject": valid({ sub: "" }),
			"no issue time": valid({ iat: undefined }),
			"an issue time as text": valid({ iat: String(seconds) }),
			"two audiences without the client as azp": valid({ aud: ["cid", "other"] }),
			"two audiences, another party authorized": valid({ aud: ["cid", "other"], azp: "other" }),
			"one audience, another party authorized": valid({ azp: "other" }),
			"a login time as text": valid({ auth_time: "yesterday" }),
			"a login time before the epoch": valid({ auth_time: -1 }),
			"a login time ahead of the clock allowance": valid({ auth_time: seconds + 31 }),
			"another nonce": valid({ nonce: "other" }),
			"no nonce": valid({ nonce: undefined }),
		};
		for (const [named, verified] of Object.entries(cases)) {
			expect(await outcome(readerOf(verified).read("t", "n")), named).toBe("refused");
		}
	});

	it("takes another authorized party of one audience only where the type takes cross-client identity", async () => {
		const crossClient = readerOf(valid({ azp: "android" }), { crossClient: true });
		expect((await crossClient.read("t", "n")).login.subject).toBe("alice");
		const several = readerOf(valid({ aud: ["cid", "x"], azp: "x" }), { crossClient: true });
		expect(await outcome(several.read("t", "n"))).toBe("refused");
	});

	it("reads the profile, its email verified only by a value the type names", async () => {
		const said = { email: "a@idp.example", name: "Alice", picture: "https://p.example/a" };
		const profileOf = async (more: Record<string, unknown>, verifiedBy = rules.emailVerified) =>
			(await readerOf(valid(more), { emailVerified: verifiedBy }).read("t", "n")).login.profile;
		expect(await profileOf({ ...said, email_verified: true })).toEqual({
			...said,
			emailVerified: true,
		});
		expect(await profileOf({ email: said.email, email_verified: "true" })).toEqual({
			email: said.email,
			emailVerified: false,
		});
		expect(await profileOf({ email: said.email, email_verified: "true" }, [true, "true"])).toEqual({
			email: said.email,
			emailVerified: true,
		});
		expect(await profileOf({ email: said.email, email_verified: "false" }, [true, "true"])).toEqual(
			{ email: said.email, emailVerified: false },
		);
		expect(await profileOf({ name: 7, email_verified: true, picture: said.picture })).toEqual({
			picture: said.picture,
		});
		expect(await profileOf({ email: 7, email_verified: true, name: "Alice", picture: 7 })).toEqual({
			name: "Alice",
		});
		expect(await profileOf({})).toBeUndefined();
	});
});
