import { testRequest } from "@mod/http/testing";
import { isUnavailable, Unavailable } from "@mod/kernel";
import type { Claim } from "@mod/oidc";
import type { Admission } from "@mod/sender-binding";
import type { AuthContext } from "@mod/session";
import type { TokenSession } from "@mod/session-tokens";
import type { AccessCheck, AccessGrant } from "@mod/tokens";
import { describe, expect, it } from "vitest";
import { userinfoOver } from "../src/userinfo.ts";

const grant: AccessGrant = {
	subject: "ann",
	issuedTo: "app",
	audience: ["app"],
	scope: ["openid", "profile"],
};
const valid = (
	tokenType = "Bearer",
	granted: AccessGrant = grant,
): Extract<AccessCheck, { kind: "valid" }> => ({
	kind: "valid",
	id: "token-1",
	grant: granted,
	expiresAt: 0,
	tokenType,
});
const open: AuthContext = { subject: "ann", amr: ["pwd"], authenticatedAt: 0 };

/** The handler over parts that answer as told, keeping the calls in order. */
function over(
	told: {
		admission?: Admission<AccessCheck>;
		session?: TokenSession;
		context?: AuthContext | undefined;
		claims?: Record<string, Claim>;
		failing?: "admitted" | "session" | "context" | "claims";
	} = {},
) {
	const calls: unknown[][] = [];
	const fail = (part: string) => {
		if (told.failing === part) throw new Unavailable(part);
	};
	const handle = userinfoOver({
		senderBinding: {
			admitted: async () => {
				calls.push(["admitted"]);
				fail("admitted");
				return (told.admission ?? { kind: "admitted", access: valid() }) as never;
			},
		},
		// Never asked here: the fake sender-binding admits without it.
		tokens: { verifyAccess: async () => valid() },
		sessionTokens: {
			sessionOf: async (id) => {
				calls.push(["session", id]);
				fail("session");
				return told.session ?? { kind: "bound", handle: "h1" };
			},
		},
		sessions: {
			openContext: async (handle) => {
				calls.push(["context", handle]);
				fail("context");
				// A context told as undefined is a session no longer open, apart from none told.
				return "context" in told ? told.context : open;
			},
		},
		claims: {
			of: async (subject, scope, handle) => {
				calls.push(["claims", subject, scope, handle]);
				fail("claims");
				return told.claims ?? { name: "Ann" };
			},
		},
	});
	const run = async () => {
		const res = await handle(testRequest());
		return { status: res.status, headers: res.headers, json: (res.body as { json: unknown }).json };
	};
	return { run, calls };
}

const noStore = { "cache-control": "no-store", pragma: "no-cache" };

describe("userinfo", () => {
	it("answers the claims oidc releases for the token's scope, with sub from the token, for its open session", async () => {
		const o = over({ claims: { name: "Ann", sub: "someone else" } as never });
		const answer = await o.run();
		expect(answer).toEqual({ status: 200, headers: noStore, json: { name: "Ann", sub: "ann" } });
		expect(o.calls).toEqual([
			["admitted"],
			["session", "token-1"],
			["context", "h1"],
			["claims", "ann", ["openid", "profile"], "h1"],
		]);
	});

	it("answers only sub for a token issued in no session", async () => {
		const o = over({ session: { kind: "unbound" } });
		expect(await o.run()).toEqual({ status: 200, headers: noStore, json: { sub: "ann" } });
		expect(o.calls.map((c) => c[0])).toEqual(["admitted", "session"]);
	});

	it("refuses a token whose session ended or is another subject's, in the token's scheme", async () => {
		const refused = {
			status: 401,
			headers: { ...noStore, "www-authenticate": 'DPoP error="invalid_token"' },
			json: { error: "invalid_token" },
		};
		const dpop = { kind: "admitted", access: valid("DPoP") } as const;
		const ended = over({ admission: dpop, context: undefined });
		expect(await ended.run()).toEqual(refused);
		expect(ended.calls.map((c) => c[0])).not.toContain("claims");
		const other = over({ admission: dpop, context: { ...open, subject: "bob" } });
		expect(await other.run()).toEqual(refused);
	});

	it("refuses a token whose scope lacks openid as insufficient_scope, in the token's scheme, before reading its session", async () => {
		for (const scope of [[], ["profile"], ["openidx"]]) {
			const o = over({
				admission: { kind: "admitted", access: valid("DPoP", { ...grant, scope }) },
				session: { kind: "unbound" },
			});
			expect(await o.run(), scope.join(" ")).toEqual({
				status: 403,
				headers: { ...noStore, "www-authenticate": 'DPoP error="insufficient_scope"' },
				json: { error: "insufficient_scope" },
			});
			expect(o.calls).toEqual([["admitted"]]);
		}
	});

	it("never reads the token's audience: a token for another audience is answered", async () => {
		const o = over({
			admission: {
				kind: "admitted",
				access: valid("Bearer", { ...grant, audience: ["elsewhere"] }),
			},
		});
		expect((await o.run()).status).toBe(200);
	});

	it("passes on sender-binding's refusal, with no error for a request with no token", async () => {
		const challenge = { "www-authenticate": "Bearer" };
		const none = over({ admission: { kind: "refused", status: 401, headers: challenge } });
		// Strict: a refusal with no error has no `error` key at all.
		expect(await none.run()).toStrictEqual({
			status: 401,
			headers: { ...noStore, ...challenge },
			json: {},
		});
		const bad = { "www-authenticate": 'Bearer error="invalid_request"' };
		const invalid = over({
			admission: { kind: "refused", status: 400, error: "invalid_request", headers: bad },
		});
		expect(await invalid.run()).toEqual({
			status: 400,
			headers: { ...noStore, ...bad },
			json: { error: "invalid_request" },
		});
		expect(invalid.calls).toEqual([["admitted"]]);
	});

	it("fails unavailable when a check or the claims cannot tell, answering no claim", async () => {
		for (const failing of ["admitted", "session", "context", "claims"] as const) {
			await expect(over({ failing }).run(), failing).rejects.toSatisfy(isUnavailable);
		}
	});
});
