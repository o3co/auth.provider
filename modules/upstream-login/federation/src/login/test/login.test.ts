import { testRequest } from "@mod/http/testing";
import type { LoginFacts } from "@mod/session";
import type { UpstreamLogin } from "@mod/upstreams";
import { expect, it } from "vitest";
import type { Completing, Idp } from "../../round-trip/round-trip.ts";
import { loginWith } from "../login.ts";

/** A round trip started at 1_800_000_000_500 ms, to an upstream whose clock may be 30 s off ours. */
const startedAt = 1_800_000_000_500;
const startSecond = 1_800_000_000_000;
const skewMs = 30_000;

/** The login continuation over stand-ins, keeping the facts it hands login-gates; the IdP's fresh login allowance its clock allowance unless given. */
function loginOf(
	upstreamAmr: ReadonlyMap<string, string> = new Map(),
	freshMs = skewMs,
	revoked = false,
) {
	const handed: LoginFacts[] = [];
	const recorded: unknown[] = [];
	const login = loginWith({
		logins: {
			login: async (_request, facts) => {
				handed.push(facts);
				if (revoked) return { kind: "revoked", cookies: [] };
				return {
					kind: "opened",
					session: { id: "s1", context: { ...facts, authenticatedAt: 0 } },
					cookies: [],
				};
			},
		},
		users: {
			byUpstream: async () => ({ kind: "user", user: { subject: "alice", attributes: {} } }),
		},
		audit: { record: (event) => void recorded.push(event) },
		handoff: { of: () => undefined },
		landing: "https://app.example/",
		heldLoginLifetimeMs: 600_000,
	});
	const completing = (upstreamLogin: UpstreamLogin): Completing => ({
		request: testRequest(),
		name: "corp",
		idp: {
			upstreamAmr,
			upstream: { clockSkewMs: skewMs },
			freshLoginAllowanceMs: freshMs,
		} as unknown as Idp,
		upstreamLogin,
		trip: { nonce: "n", verifier: "v", startedAt },
		cleared: [],
	});
	return { handed, recorded, complete: (at: UpstreamLogin) => login.complete(completing(at)) };
}

it("reports when the upstream says the user logged in, or that it is unknown where it says nothing", async () => {
	const l = loginOf();
	await l.complete({ subject: "u-1", amr: [], authenticatedAt: 1_800_000_001_000 });
	await l.complete({ subject: "u-1", amr: [] });
	expect(l.handed.map((facts) => facts.authenticatedAt)).toEqual([1_800_000_001_000, "unknown"]);
});

it("reports a login the upstream says came within its clock allowance before the start as made at the start [guarantee-2-c]", async () => {
	const l = loginOf();
	for (const authenticatedAt of [
		startSecond - skewMs,
		startSecond - 1,
		// Said in the start's own second, which the upstream gives only whole: before the start to the millisecond.
		startSecond,
		startSecond - skewMs - 1000,
	]) {
		await l.complete({ subject: "u-1", amr: [], authenticatedAt });
	}
	// Within the allowance it is our start to the millisecond, as the upstream's clock is mapped to ours; older stays as said.
	expect(l.handed.map((facts) => facts.authenticatedAt)).toEqual([
		startedAt,
		startedAt,
		startedAt,
		startSecond - skewMs - 1000,
	]);
});

it("moves a login to the start by the IdP's fresh login allowance, not its clock allowance, where the two differ [guarantee-2-c]", async () => {
	const l = loginOf(new Map(), 5000);
	// Within the type's 30 s, but not the 5 s set: it stays as said, asked for no fresh login or not.
	await l.complete({ subject: "u-1", amr: [], authenticatedAt: startSecond - 10_000 });
	await l.complete({ subject: "u-1", amr: [], authenticatedAt: startSecond - 5000 });
	expect(l.handed.map((facts) => facts.authenticatedAt)).toEqual([startSecond - 10_000, startedAt]);
});

it("reports a login the upstream says came after the start as said", async () => {
	const l = loginOf();
	await l.complete({ subject: "u-1", amr: [], authenticatedAt: startSecond + 5000 });
	expect(l.handed.map((facts) => facts.authenticatedAt)).toEqual([startSecond + 5000]);
});

it("states the round trip's start as the proof's start session compares, and answers a login session revoked as one with no local user", async () => {
	const l = loginOf();
	await l.complete({ subject: "u-1", amr: [] });
	expect(l.handed.map((facts) => facts.provenSince)).toEqual([startedAt]);
	const revoked = loginOf(new Map(), skewMs, true);
	const answered = await revoked.complete({ subject: "u-1", amr: [] });
	expect(answered.status).toBe(401);
	expect(answered.body).toEqual({ json: { error: "unknown_user" } });
	expect(JSON.stringify(revoked.recorded)).toContain("revoked");
});

it("names each amr once, however many upstream values map to it", async () => {
	const l = loginOf(
		new Map([
			["a", "otp"],
			["b", "otp"],
			["c", "fed"],
		]),
	);
	await l.complete({ subject: "u-1", amr: ["a", "b", "c", "a"] });
	expect(l.handed.map((facts) => facts.amr)).toEqual([["fed", "otp"]]);
});

it("keeps only a string email, and gives no attributes where the upstream gave no profile", async () => {
	const l = loginOf();
	const profile = { email: 7, emailVerified: true } as unknown as NonNullable<
		UpstreamLogin["profile"]
	>;
	await l.complete({ subject: "u-1", amr: [], profile });
	await l.complete({ subject: "u-1", amr: [] });
	expect(l.handed.map((facts) => facts.attributes?.values)).toEqual([{}, undefined]);
	expect(l.handed.map((facts) => "attributes" in facts)).toEqual([true, false]);
});

it("answers a login a gate refuses as one with no local user, recording why, keeping no tokens", async () => {
	const recorded: unknown[] = [];
	const after: string[] = [];
	const login = loginWith({
		logins: { login: async () => ({ kind: "refused", gate: "credential-policy", cookies: [] }) },
		users: {
			byUpstream: async () => ({ kind: "user", user: { subject: "alice", attributes: {} } }),
		},
		audit: { record: (event) => void recorded.push(event) },
		handoff: {
			of: () => ({
				carry: "c",
				deadline: 0,
				after: async (outcome) => void after.push(outcome.kind),
			}),
		},
		landing: "https://app.example/",
		heldLoginLifetimeMs: 600_000,
	});
	const answer = await login.complete({
		request: testRequest(),
		name: "corp",
		idp: { upstreamAmr: new Map(), upstream: {} } as unknown as Idp,
		upstreamLogin: { subject: "u-alice", amr: [] } as unknown as UpstreamLogin,
		trip: { nonce: "n", verifier: "v", startedAt },
		cleared: ["trip=; Max-Age=0"],
	});
	expect(answer).toMatchObject({ status: 401, body: { json: { error: "unknown_user" } } });
	expect(answer.cookies).toEqual(["trip=; Max-Age=0"]);
	expect(after).toEqual(["refused"]);
	expect(recorded).toEqual([
		expect.objectContaining({
			kind: "federation.login.failed",
			attributes: expect.objectContaining({ reason: "refused" }),
		}),
	]);
});
