import { testRequest } from "@mod/http/testing";
import type { LoginFacts } from "@mod/session";
import type { UpstreamLogin } from "@mod/upstreams";
import { expect, it } from "vitest";
import { loginWith } from "../login.ts";
import type { Completing, Idp } from "../round-trip.ts";

/** A round trip started at 1_800_000_000_500 ms, to an upstream whose clock may be 30 s off ours. */
const startedAt = 1_800_000_000_500;
const startSecond = 1_800_000_000_000;
const skewMs = 30_000;

/** The login continuation over stand-ins, keeping the facts it hands login-gates. */
function loginOf(upstreamAmr: ReadonlyMap<string, string> = new Map()) {
	const handed: LoginFacts[] = [];
	const login = loginWith({
		logins: {
			login: async (_request, facts) => {
				handed.push(facts);
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
		audit: { record: () => {} },
		handoff: { of: () => undefined },
		landing: "https://app.example/",
	});
	const completing = (upstreamLogin: UpstreamLogin): Completing => ({
		request: testRequest(),
		name: "corp",
		idp: { upstreamAmr, upstream: { clockSkewMs: skewMs } } as unknown as Idp,
		upstreamLogin,
		transaction: { format: 1, idp: "corp", state: "st", nonce: "n", verifier: "v", startedAt },
		cleared: [],
	});
	return { handed, complete: (at: UpstreamLogin) => login.complete(completing(at)) };
}

it("reports when the upstream says the user logged in, or that it is unknown where it says nothing", async () => {
	const l = loginOf();
	await l.complete({ subject: "u-1", amr: [], authenticatedAt: 1_800_000_001_000 });
	await l.complete({ subject: "u-1", amr: [] });
	expect(l.handed.map((facts) => facts.authenticatedAt)).toEqual([1_800_000_001_000, "unknown"]);
});

it("reports a login the upstream says came within its clock allowance before the start as made at the start", async () => {
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

it("reports a login the upstream says came after the start as said", async () => {
	const l = loginOf();
	await l.complete({ subject: "u-1", amr: [], authenticatedAt: startSecond + 5000 });
	expect(l.handed.map((facts) => facts.authenticatedAt)).toEqual([startSecond + 5000]);
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
