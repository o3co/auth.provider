import type { Target } from "@mod/claims-selection";
import { testRequest } from "@mod/http/testing";
import { isUnavailable, Unavailable } from "@mod/kernel";
import type { Claim } from "@mod/oidc";
import type { Admission } from "@mod/sender-binding";
import type { AuthContext, Entry } from "@mod/session";
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
const issuer = "https://issuer.example";
/** A token issued for `granted`, the issuer among the audiences its issuer added unless `added` says otherwise. */
const valid = (
	tokenType = "Bearer",
	granted: AccessGrant = grant,
	added: readonly string[] = [issuer],
): Extract<AccessCheck, { kind: "valid" }> => ({
	kind: "valid",
	id: "token-1",
	grant: granted,
	expiresAt: 1000,
	tokenType,
	...(added.length > 0 ? { addedAudience: added } : {}),
});
const open: AuthContext = { subject: "ann", amr: ["pwd"], authenticatedAt: 0 };
const entered = (context: AuthContext): Entry => ({
	kind: "entered",
	session: { id: "h1", context },
	endsAt: 1,
});

/** The handler over parts that answer as told, keeping the calls in order. */
function over(
	told: {
		admission?: Admission<AccessCheck>;
		session?: TokenSession;
		entry?: Entry;
		claims?: Record<string, Claim>;
		selection?: Target;
		/** Runs while the selection is read, as a host that stalls there. */
		duringSelection?: (clock: { at: number }) => void;
		failing?: "admitted" | "session" | "entry" | "selection" | "claims";
		/** Whether a token not for the issuer is refused: `issuer-audience` `on` unless said otherwise. */
		requiresIssuer?: boolean;
	} = {},
) {
	const calls: unknown[][] = [];
	const clock = { at: 0 };
	const fail = (part: string) => {
		if (told.failing === part) throw new Unavailable(part);
	};
	const handle = userinfoOver({
		now: () => clock.at,
		issuer,
		requiresIssuer: told.requiresIssuer ?? true,
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
			entryOf: async (handle, level) => {
				calls.push(level === undefined ? ["entry", handle] : ["entry", handle, level]);
				fail("entry");
				return told.entry ?? entered(open);
			},
		},
		selections: {
			forToken: async (id) => {
				calls.push(["selection", id]);
				fail("selection");
				told.duringSelection?.(clock);
				return told.selection;
			},
		},
		claims: {
			of: async (subject, scope, handle, asked) => {
				calls.push(["claims", subject, scope, handle, asked]);
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
	it("answers the claims oidc releases for the token's scope, with sub from the token, for its open session [oidc-core-5.3.2-a] [oidc-core-5.3.2-d]", async () => {
		const o = over({ claims: { name: "Ann", sub: "someone else" } as never });
		const answer = await o.run();
		expect(answer).toEqual({ status: 200, headers: noStore, json: { name: "Ann", sub: "ann" } });
		expect(o.calls).toEqual([
			["admitted"],
			["session", "token-1"],
			["entry", "h1"],
			["selection", "token-1"],
			["claims", "ann", ["openid", "profile"], "h1", undefined],
		]);
	});

	it("hands oidc the selection kept for the token: the names it asks beyond its scope, and the constraints", async () => {
		const selection: Target = {
			names: [{ name: "email", scope: "email" }],
			constraints: [{ name: "name", value: "Ann" }],
		};
		const o = over({ selection });
		expect((await o.run()).status).toBe(200);
		expect(o.calls.at(-1)).toEqual(["claims", "ann", ["openid", "profile"], "h1", selection]);
	});

	it("refuses a token that ends while it is answered, read once its selection is, never answering without it", async () => {
		const refused = {
			status: 401,
			headers: { ...noStore, "www-authenticate": 'Bearer error="invalid_token"' },
			json: { error: "invalid_token" },
		};
		// Checked just before its end; the read of its selection stalls past its end and the two minutes after.
		const stalled = over({
			duringSelection: (clock) => {
				clock.at = 1000 + 120_000 + 1;
			},
		});
		expect(await stalled.run()).toEqual(refused);
		expect(stalled.calls.map((c) => c[0])).not.toContain("claims");
		// At its end exactly, it has ended too; a moment before, it is answered.
		const ended = over({ duringSelection: (clock) => (clock.at = 1000) });
		expect(await ended.run()).toEqual(refused);
		const inTime = over({ duringSelection: (clock) => (clock.at = 999) });
		expect((await inTime.run()).status).toBe(200);
	});

	it("reads no selection for a token issued in no session, or one whose session ended, and answers 503 when it cannot read one", async () => {
		expect((await over({ session: { kind: "unbound" } }).run()).status).toBe(200);
		const unbound = over({ session: { kind: "unbound" } });
		await unbound.run();
		const ended = over({ entry: { kind: "absent" } });
		await ended.run();
		for (const o of [unbound, ended]) expect(o.calls.map((c) => c[0])).not.toContain("selection");
		const failing = over({ failing: "selection" });
		await expect(failing.run()).rejects.toSatisfy(isUnavailable);
		expect(failing.calls.map((c) => c[0])).not.toContain("claims");
	});

	it("answers only sub for a token issued in no session [oidc-core-5.3.2-d]", async () => {
		const o = over({ session: { kind: "unbound" } });
		expect(await o.run()).toEqual({ status: 200, headers: noStore, json: { sub: "ann" } });
		expect(o.calls.map((c) => c[0])).toEqual(["admitted", "session"]);
	});

	it("refuses a token whose session ended, is short of a requirement, or is another subject's, in the token's scheme [rfc9449-7.1-c] [rfc6749-7.2-a]", async () => {
		const refused = {
			status: 401,
			headers: { ...noStore, "www-authenticate": 'DPoP error="invalid_token"' },
			json: { error: "invalid_token" },
		};
		const dpop = { kind: "admitted", access: valid("DPoP") } as const;
		const ended = over({ admission: dpop, entry: { kind: "absent" } });
		expect(await ended.run()).toEqual(refused);
		expect(ended.calls.map((c) => c[0])).not.toContain("claims");
		// Short at use: refused as an ended session is, never the requirement's own answer.
		const short = over({
			admission: dpop,
			entry: { kind: "short", requirement: "mfa", answer: { error: "mfa_required" } },
		});
		expect(await short.run()).toEqual(refused);
		expect(short.calls.map((c) => c[0])).not.toContain("claims");
		const other = over({ admission: dpop, entry: entered({ ...open, subject: "bob" }) });
		expect(await other.run()).toEqual(refused);
	});

	it("refuses a token whose scope lacks openid as insufficient_scope, in the token's scheme, before reading its session [rfc6750-3.1-c] [rfc9449-7.1-c]", async () => {
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

	it("refuses a token not for the issuer as invalid_token, in the token's scheme, before reading its session [rfc9700-2.3-c]", async () => {
		const o = over({ admission: { kind: "admitted", access: valid("DPoP", grant, []) } });
		expect(await o.run()).toEqual({
			status: 401,
			headers: { ...noStore, "www-authenticate": 'DPoP error="invalid_token"' },
			json: { error: "invalid_token" },
		});
		expect(o.calls).toEqual([["admitted"]]);
	});

	it("answers a token not for the issuer where the issuer is not required of it, as adding and off leave it", async () => {
		const o = over({
			admission: { kind: "admitted", access: valid("Bearer", grant, []) },
			requiresIssuer: false,
		});
		expect((await o.run()).status).toBe(200);
	});

	it("answers a token whose grant's audience is the issuer itself, nothing added to it [rfc9700-2.3-c]", async () => {
		const own = { ...grant, audience: [issuer] };
		const o = over({ admission: { kind: "admitted", access: valid("Bearer", own, []) } });
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
		for (const failing of ["admitted", "session", "entry", "claims"] as const) {
			await expect(over({ failing }).run(), failing).rejects.toSatisfy(isUnavailable);
		}
	});
});
