import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import { originEvidence } from "@mod/csrf";
import { type GrantOutcome, sessionIssuances } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	BootRefused,
	defineModule,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { type Entry, type Session, sessions } from "@mod/session";
import { stubSessions } from "@mod/session/testing";
import { sessionTokens } from "@mod/session-tokens";
import sessionTokensModule from "@mod/session-tokens/module";
import { sessionTokensInMemory } from "@mod/session-tokens/testing";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import {
	type IssuanceRequest,
	issuancePolicies,
	referenceOf,
	type Tokens,
	tokens,
} from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { describe, expect, it } from "vitest";
import sessionGrant from "../src/module.ts";

const now = 1_800_000_000_000;
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n).map(() => Math.floor(Math.random() * 256)) },
});
const ours = "https://issuer.example";
const api = "https://api.example";
const allowed = allowancesFor({
	grants: ["session"],
	scopes: ["read", "write"],
	"default-scopes": ["read"],
	audiences: [api],
});
const enteredWith = (context: Session["context"], endsAt = now + 3_600_000): Entry => ({
	kind: "entered",
	session: { id: "h", context },
	endsAt,
});
const login = { subject: "alice", amr: ["pwd"], authenticatedAt: now - 1000 };
const entered = enteredWith(login);

interface Options {
	/** What entry answers. */
	readonly entry?: Entry;
	/** What recording a token does, after noting it. */
	readonly recording?: () => void;
	/** Whether the session can no longer be entered once the token is recorded: closed, or short of a requirement. */
	readonly closesWhileRecording?: true | "short";
	/** Whether the session cannot tell if it is still open once the token is recorded. */
	readonly cannotTellOpen?: true;
	readonly extra?: readonly Module[];
	/** Whether nothing records the tokens issued from a session. */
	readonly untold?: boolean;
}

async function serve(options: Options = {}) {
	const recorded = new Map<string, string>();
	const revoked: string[] = [];
	const asked: string[] = [];
	let after: Entry = entered;
	const standIn = tokensStandIn();
	// The stand-in, with every revocation by reference noted.
	const watched = {
		...standIn,
		provides: (standIn.provides ?? []).map((part) => ({
			contract: part.contract,
			create: async (c: Parameters<typeof part.create>[0]) => {
				const given = (await part.create(c)) as Tokens;
				return {
					...given,
					revokeReferenced: async (reference: string) => {
						revoked.push(reference);
						return given.revokeReferenced(reference);
					},
				};
			},
		})),
	};
	const stubs = defineModule({ name: "stubs", replicaSafe: false, takes: [] }, (m) => [
		m.provide(originEvidence).by(() => ({
			sameOrigin: (request) => request.headers.get("origin") === ours,
		})),
		m.provide(sessions).by(() =>
			stubSessions({
				enterFor: async (_, level) => {
					asked.push(level);
					return options.entry ?? entered;
				},
				entryOf: async () => {
					if (options.cannotTellOpen) throw new Unavailable("session");
					return after;
				},
			}),
		),
	]);
	const telling = defineModule({ name: "telling", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(sessionIssuances).by(() => ({
			issued: async (session, issued) => {
				recorded.set(referenceOf(issued), session);
				if (options.closesWhileRecording === true) after = { kind: "absent" };
				if (options.closesWhileRecording === "short") {
					after = { kind: "short", requirement: "mfa", answer: { error: "mfa_required" } };
				}
				options.recording?.();
			},
		})),
	]);
	const app = await assemble({
		modules: [
			http,
			watched,
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			stubs,
			...(options.untold ? [] : [telling]),
			sessionGrant,
			...(options.extra ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...issuerConfig(),
			...clientsConfig([
				confidentialClient({ id: "app", sections: allowed }),
				publicClient({ id: "spa", sections: allowed }),
				confidentialClient({
					id: "bare",
					sections: allowancesFor({ grants: ["session"], scopes: ["read"] }),
				}),
			]),
		},
		runtime,
	});
	const issuing = app.get(tokens);
	const from = (origin: string | null) =>
		testRequest({ method: "POST", headers: new Map(origin ? [["origin", origin]] : []) });
	const call = (as: string, params: Record<string, string> = {}, origin: string | null = ours) =>
		app
			.get(grantCalls)
			.call("session", as, { grant_type: "session", ...params }, { request: from(origin) });
	const issued = async (outcome: GrantOutcome) => {
		if (outcome.kind !== "issued") throw new Error(`${outcome.error}: ${outcome.description}`);
		const checked = await issuing.verifyAccess(String(outcome.body.access_token));
		if (checked.kind !== "valid") throw new Error(checked.reason);
		return checked;
	};
	return { app, call, issued, recorded, revoked, asked };
}

describe("session-grant", () => {
	it("issues an access token for the session's subject to a confidential or a public client [rfc6749-3.3-a] [rfc6749-3.3-b]", async () => {
		const s = await serve();
		for (const client of ["app", "spa"]) {
			const outcome = await s.call(client);
			expect(outcome).toMatchObject({
				kind: "issued",
				body: { token_type: "Bearer", expires_in: expect.any(Number), scope: "read" },
			});
			expect(outcome).not.toHaveProperty("body.refresh_token");
			const checked = await s.issued(outcome);
			expect(checked.grant).toEqual({
				subject: "alice",
				issuedTo: client,
				audience: [api],
				scope: ["read"],
				amr: ["pwd"],
				authenticatedAt: now - 1000,
			});
			expect(s.recorded.get(referenceOf(checked))).toBe("h");
		}
		expect(s.asked).toEqual(["use", "use"]);
	});

	it("refuses to boot where nothing records its tokens to their session, and boots where something does", async () => {
		await expect(serve({ untold: true })).rejects.toBeInstanceOf(BootRefused);
		await expect(
			serve({ untold: true, extra: [sessionTokensModule, sessionTokensInMemory().module] }),
		).resolves.toBeDefined();
	});

	it("has its token recorded to the session, as session-tokens answers it", async () => {
		const s = await serve({ extra: [sessionTokensModule, sessionTokensInMemory().module] });
		const checked = await s.issued(await s.call("app"));
		expect(await s.app.get(sessionTokens).sessionOf(checked.id)).toEqual({
			kind: "bound",
			handle: "h",
		});
	});

	it("gives the scope asked within the client's allowance, and no scope outside it [rfc6749-10.3-c]", async () => {
		const s = await serve();
		expect((await s.issued(await s.call("app", { scope: "read write" }))).grant.scope).toEqual([
			"read",
			"write",
		]);
		expect(await s.call("app", { scope: "admin" })).toMatchObject({ error: "invalid_scope" });
		// The body's client_id names nobody here: only the authenticated client's allowance counts.
		expect(await s.call("bare", { scope: "write", client_id: "app" })).toMatchObject({
			error: "invalid_scope",
		});
	});

	it("refuses a request without same-origin evidence as unauthorized, before reading the session", async () => {
		const s = await serve();
		for (const origin of [null, "https://elsewhere.example"]) {
			expect(await s.call("app", {}, origin)).toEqual({
				kind: "error",
				error: "unauthorized",
				description: "session is not authenticated",
				status: 401,
			});
		}
		expect(s.asked).toEqual([]);
	});

	it("refuses without a session as unauthorized, and names the requirement a session falls short of", async () => {
		const absent = await serve({ entry: { kind: "absent" } });
		expect(await absent.call("app")).toMatchObject({ error: "unauthorized", status: 401 });
		const short = await serve({
			entry: { kind: "short", requirement: "mfa", answer: { error: "mfa_required" } },
		});
		expect(await short.call("app")).toEqual({
			kind: "error",
			error: "invalid_grant",
			description: "the session must step up through mfa",
			members: { step_up: "mfa" },
		});
	});

	it("issues no authentication time from a session that does not know it", async () => {
		const s = await serve({ entry: enteredWith({ ...login, authenticatedAtUnknown: true }) });
		// tokens answers no authentication time for a token issued without one known.
		expect((await s.issued(await s.call("app"))).grant).not.toHaveProperty("authenticatedAt");
		const known = await serve();
		expect((await known.issued(await known.call("app"))).grant).toHaveProperty("authenticatedAt");
	});

	it("never issues a token that outlives its session", async () => {
		const s = await serve({ entry: enteredWith(login, now + 120_000) });
		const checked = await s.issued(await s.call("app"));
		expect(checked.expiresAt).toBeLessThanOrEqual(now + 120_000);
	});

	it("issues through the issuance policies from the session entered, recording nothing they refuse", async () => {
		const asked: IssuanceRequest[] = [];
		const refusing = defineModule({ name: "refusing", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async (request) => {
					asked.push(request);
					return { kind: "refused", reason: "test_reason", description: "refused here" };
				},
			})),
		]);
		const s = await serve({ extra: [refusing] });
		expect(await s.call("app")).toEqual({
			kind: "error",
			error: "invalid_grant",
			description: "refused here",
		});
		expect(asked.map(({ grantType, session }) => [grantType, session])).toEqual([["session", "h"]]);
		expect(s.recorded.size).toBe(0);
	});

	it("asks the issuance policies once for each token it issues", async () => {
		const asked: IssuanceRequest[] = [];
		const allowing = defineModule({ name: "allowing", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async (request) => {
					asked.push(request);
					return { kind: "allowed" };
				},
			})),
		]);
		const s = await serve({ extra: [allowing] });
		await s.issued(await s.call("app"));
		expect(asked).toHaveLength(1);
	});

	it("refuses a session that authenticated far ahead of the clock", async () => {
		const s = await serve({ entry: enteredWith({ ...login, authenticatedAt: now + 300_001 }) });
		expect(await s.call("app")).toMatchObject({ kind: "error", error: "invalid_grant" });
		expect(s.recorded.size).toBe(0);
	});

	it("revokes what it issued and refuses when the session can no longer be entered once the token is recorded", async () => {
		const s = await serve({ closesWhileRecording: true });
		expect(await s.call("app")).toEqual({
			kind: "error",
			error: "invalid_grant",
			description: "session_invalid",
		});
		expect(s.recorded.size).toBe(1);
		expect(s.revoked).toEqual([...s.recorded.keys()]);
	});

	it("revokes what it issued and refuses when the session falls short of a requirement while it is recorded", async () => {
		const s = await serve({ closesWhileRecording: "short" });
		expect(await s.call("app")).toEqual({
			kind: "error",
			error: "invalid_grant",
			description: "session_invalid",
		});
		expect(s.recorded.size).toBe(1);
		expect(s.revoked).toEqual([...s.recorded.keys()]);
	});

	it("revokes what it issued and passes the failure on when the session cannot tell it is still open", async () => {
		const s = await serve({ cannotTellOpen: true });
		await expect(s.call("app")).rejects.toThrow(Unavailable);
		expect(s.recorded.size).toBe(1);
		expect(s.revoked).toEqual([...s.recorded.keys()]);
	});

	it("passes on a failure to record the token, which is revoked", async () => {
		const s = await serve({
			recording: () => {
				throw new Unavailable("session-tokens");
			},
		});
		await expect(s.call("app")).rejects.toThrow(Unavailable);
		expect(s.revoked).toEqual([...s.recorded.keys()]);
	});
});
