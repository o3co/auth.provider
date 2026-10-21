import { describe, expect, it } from "vitest";
import { credentialsFrom, permits, scopeTokens } from "../grant.ts";

const shown = ["openid", "offline_access", "read"];
const at = { now: 1000, maxAccessMs: 3_600_000, shown };

/** Tokens an upstream gives, bearer with a refresh token and five minutes, unless a case says. */
const upstreamTokens = (more: Readonly<Record<string, unknown>> = {}) => ({
	accessToken: "up-1",
	tokenType: "Bearer",
	refreshToken: "up-refresh-1",
	expiresInSeconds: 300,
	scope: shown,
	...more,
});

/** An upstream's tokens over the default, any refresh token already held, and `held <scopes>` or `refused <why>`. */
const tokenCases: readonly {
	readonly name: string;
	readonly tokens: Readonly<Record<string, unknown>>;
	readonly held?: string;
	readonly said: string;
}[] = [
	{ name: "holds a bearer token", tokens: {}, said: "held openid offline_access read" },
	{
		name: "takes bearer in any case",
		tokens: { tokenType: "bearer" },
		said: "held openid offline_access read",
	},
	{
		name: "takes no scope said as all shown",
		tokens: { scope: [] },
		said: "held openid offline_access read",
	},
	{ name: "keeps a narrower scope", tokens: { scope: ["openid"] }, said: "held openid" },
	{
		name: "reads a scope with a part not text as none said",
		tokens: { scope: ["openid", 5] },
		said: "held openid offline_access read",
	},
	{
		name: "keeps the held refresh token",
		tokens: { refreshToken: undefined },
		held: "r-0",
		said: "held openid offline_access read",
	},
	{
		name: "lives exactly the longest",
		tokens: { expiresInSeconds: 3600 },
		said: "held openid offline_access read",
	},
	{
		name: "refuses no refresh token",
		tokens: { refreshToken: undefined },
		said: "refused refresh_token_absent",
	},
	{
		name: "refuses an empty refresh token",
		tokens: { refreshToken: "" },
		said: "refused refresh_token_absent",
	},
	{
		name: "refuses no access token",
		tokens: { accessToken: undefined },
		said: "refused upstream_token_ineligible",
	},
	{
		name: "refuses an empty access token",
		tokens: { accessToken: "" },
		said: "refused upstream_token_ineligible",
	},
	{
		name: "refuses a life of zero",
		tokens: { expiresInSeconds: 0 },
		said: "refused upstream_token_ineligible",
	},
	{
		name: "refuses an endless life",
		tokens: { expiresInSeconds: Number.POSITIVE_INFINITY },
		said: "refused upstream_token_ineligible",
	},
	{
		name: "refuses a life past the longest",
		tokens: { expiresInSeconds: 3601 },
		said: "refused upstream_token_ineligible",
	},
	{
		name: "refuses a scope wider than shown",
		tokens: { scope: ["openid", "write"] },
		said: "refused scope_exceeded",
	},
	{
		name: "refuses another type",
		tokens: { tokenType: "DPoP" },
		said: "refused upstream_token_ineligible",
	},
];

describe("judging an upstream's tokens", () => {
	for (const c of tokenCases) {
		it(c.name, () => {
			const read = credentialsFrom(upstreamTokens(c.tokens), {
				...at,
				...(c.held ? { held: c.held } : {}),
			});
			const said =
				read.kind === "held" ? `held ${read.credentials.scope.join(" ")}` : `refused ${read.why}`;
			expect(said).toBe(c.said);
		});
	}

	it("reads a part that throws as none, and keeps a rotated refresh token it refuses the rest of", () => {
		const throwing = Object.defineProperty({ ...upstreamTokens() }, "tokenType", {
			get: () => {
				throw new Error("no");
			},
		});
		expect(credentialsFrom(throwing, at)).toMatchObject({
			kind: "refused",
			refreshToken: "up-refresh-1",
		});
	});

	it("keeps the earlier end for the access token it holds, its life counted from now; a new token as said", () => {
		const kept = { accessToken: "up-1", expiresAt: at.now + 25_000 };
		const ends = (tokens: Readonly<Record<string, unknown>>) => {
			const read = credentialsFrom(upstreamTokens(tokens), { ...at, kept });
			return read.kind === "held" ? [read.credentials.expiresAt, read.credentials.obtainedAt] : [];
		};
		expect(ends({ expiresInSeconds: 600 })).toEqual([at.now + 25_000, at.now]);
		expect(ends({ expiresInSeconds: 10 })).toEqual([at.now + 10_000, at.now]);
		expect(ends({ accessToken: "up-2", expiresInSeconds: 600 })).toEqual([
			at.now + 600_000,
			at.now,
		]);
	});
});

describe("a client's permission", () => {
	it("permits only an operator's confidential client listing the connection", () => {
		const section = () => ({ connections: ["cal"], "return-uris": [] });
		const client = (registered: boolean, kind: string) => ({ registered, kind, section }) as never;
		expect(permits(client(true, "confidential"), "cal")).toBe(true);
		expect(permits(client(false, "confidential"), "cal")).toBe(false);
		expect(permits(client(true, "public"), "cal")).toBe(false);
		expect(permits(client(true, "confidential"), "mail")).toBe(false);
	});

	it("reads a scope's tokens once each, and none from anything else", () => {
		expect(scopeTokens("read read openid")).toEqual(["read", "openid"]);
		expect(scopeTokens("read  openid")).toBeUndefined();
	});
});
