import { type SessionIssuance, sessionIssuances } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import {
	assemble,
	BootRefused,
	type Contract,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime, recordingLog, switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import { sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { referenceOf, type Tokens, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { afterEach, beforeEach, expect, it } from "vitest";
import { sessionTokens } from "../src/contract.ts";
import sessionTokensModule from "../src/module.ts";
import { issuedInMemory } from "./issued.ts";

const start = 1_800_000_000_000;
let now = start;
/** module.ts's allowance past a token's expiry. */
const allowanceMs = 120_000;
const recorded = recordingLog();
/** The log's events since the test began. */
let logFrom = 0;
const loggedEvents = () =>
	recorded
		.lines()
		.slice(logFrom)
		.map((line) => line.event);
beforeEach(() => {
	now = start;
	logFrom = recorded.lines().length;
});
/** The grant every test issues for. */
const grant = { subject: "alice", issuedTo: "app", audience: ["api"], scope: [] };
/** An access token `t` issues for the grant, under the issuance policies. */
async function issuedAccess(t: Tokens) {
	const issued = await t.issue({ grant, grantType: "test" });
	if (issued.kind !== "issued") throw new Error(issued.reason);
	return issued.access;
}
const runtime = quietRuntime({ clock: { now: () => now }, log: recorded.log });

let stop = async () => {};
afterEach(() => stop());

/** What modules contribute to `token-endpoint`'s session issuances, read back after assembly. */
const told = contract<readonly SessionIssuance[]>("told");
const telling = defineModule({ name: "telling" }, (m) => [
	m.provide(told).by((c) => c.collect(sessionIssuances)),
]);
/** Records a token as token-endpoint does: by telling session-tokens it was issued from a session. */
const recording =
	(app: { get<T>(c: Contract<T>): T }) =>
	(session: string, token: { readonly id: string; readonly expiresAt: number }) => {
		const [one] = app.get(told);
		if (!one) throw new Error("session-tokens tells nothing");
		return one.issued(session, token);
	};

async function boot(
	options: {
		revocation?: "denylist" | "unsupported";
		size?: number;
		margin?: number;
		tokens?: Module;
	} = {},
) {
	const issued = issuedInMemory(options.size);
	const down = unavailableSwitch<Tokens>("tokens");
	const app = await assemble({
		modules: [
			http,
			options.tokens ??
				switchedModule(
					tokensStandIn({ revocable: options.revocation !== "unsupported" }),
					tokens,
					down,
				),
			sessionStandIn,
			subjectRevocationStandIn,
			issued.module,
			sessionTokensModule,
			telling,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			"session-tokens": { "sweep-interval": "1s", "push-out-margin": options.margin ?? 0 },
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const opened = app.get(sessions);
	const { session } = await opened.complete(testRequest(), {
		subject: "alice",
		amr: ["pwd"],
		authenticatedAt: runtime.clock.now(),
	});
	const t = app.get(tokens);
	const issue = async () => {
		const token = await issuedAccess(t);
		await recording(app)(session.id, token);
		return token;
	};
	return { issued, down, opened, session, t, issue, app };
}

it("revokes every token issued for a session when it closes, and none of another's", async () => {
	const s = await boot();
	const a = await s.issue();
	const b = await s.issue();
	const other = await issuedAccess(s.t);
	expect((await s.opened.close(s.session.id)).kind).toBe("closed");
	for (const token of [a, b])
		expect(await s.t.verifyAccess(token.token)).toEqual({ kind: "invalid", reason: "revoked" });
	expect((await s.t.verifyAccess(other.token)).kind).toBe("valid");
});

it("leaves the session closing when it cannot revoke yet, and revokes on the next close", async () => {
	const s = await boot();
	const a = await s.issue();
	s.down.unavailable("revokeAccess", "revokeReferenced");
	expect((await s.opened.close(s.session.id)).kind).toBe("pending");
	expect((await s.t.verifyAccess(a.token)).kind).toBe("valid");
	s.down.restore();
	expect((await s.opened.close(s.session.id)).kind).toBe("closed");
	expect(await s.t.verifyAccess(a.token)).toEqual({ kind: "invalid", reason: "revoked" });
});

it("refuses to start where access tokens cannot be revoked", async () => {
	await expect(boot({ revocation: "unsupported" })).rejects.toBeInstanceOf(BootRefused);
});

it("past the place's size, revokes the token that ends first and records the new one", async () => {
	const s = await boot({ size: 2 });
	const a = await s.issue();
	now += 1000;
	const b = await s.issue();
	now += 1000;
	const c = await s.issue();
	expect(await s.t.verifyAccess(a.token)).toEqual({ kind: "invalid", reason: "revoked" });
	expect(loggedEvents()).toContain("session-tokens.pushed_out");
	expect(await s.issued.sets.awaiting(s.session.id)).toEqual([]);
	expect(await s.issued.pendingListed()).toEqual([]);
	await s.opened.close(s.session.id);
	for (const token of [b, c])
		expect(await s.t.verifyAccess(token.token)).toEqual({ kind: "invalid", reason: "revoked" });
});

it("keeps each token for its remaining lifetime plus an allowance, on the kernel's clock", async () => {
	const s = await boot();
	const a = await s.issue();
	now += 1000;
	const b = await s.issue();
	const left = b.expiresAt - now;
	expect(await s.issued.sets.members(s.session.id)).toEqual(
		[
			{ member: referenceOf(a), remainingMs: left - 1000 + allowanceMs },
			{ member: referenceOf(b), remainingMs: left + allowanceMs },
		].sort((x, y) => (x.member < y.member ? -1 : 1)),
	);
	now += left + allowanceMs - 1;
	expect((await s.issued.sets.members(s.session.id)).map((m) => m.member)).toEqual([
		referenceOf(b),
	]);
});

/** Fills the session's set before the next add, as records made at the same time would. */
const crowdNextAdd = (s: Awaited<ReturnType<typeof boot>>, count: number) =>
	s.issued.beforeNextAdd(async () => {
		for (let i = 0; i < count; i++) await s.issued.crowd.add(s.session.id, `x-${i}`, 86_400_000);
	});

it("keeps every pushed-out reference awaiting with its session listed, and the sweep revokes what is left", async () => {
	const s = await boot({ size: 3 });
	const a = await s.issue();
	now += 1;
	// Adds at once past the margin: the session is listed after the add.
	crowdNextAdd(s, 3);
	s.down.failNext("revokeReferenced");
	await expect(s.issue()).rejects.toSatisfy(isUnavailable);
	const awaiting = await s.issued.sets.awaiting(s.session.id);
	expect(awaiting).toHaveLength(2);
	expect(awaiting).toContain(referenceOf(a));
	expect(await s.issued.pendingListed()).toEqual([s.session.id]);
	expect((await s.t.verifyAccess(a.token)).kind).toBe("valid");
	await new Promise((resolve) => setTimeout(resolve, 1300));
	expect(await s.t.verifyAccess(a.token)).toEqual({ kind: "invalid", reason: "revoked" });
	expect(await s.issued.sets.awaiting(s.session.id)).toEqual([]);
	expect(await s.issued.pendingListed()).toEqual([]);
});

it("lists a session before an add within the margin of its cap, and not before one further below", async () => {
	const s = await boot({ size: 4, margin: 1 });
	const listedAtAdd: string[][] = [];
	const watch = () =>
		s.issued.beforeNextAdd(async () => {
			listedAtAdd.push(await s.issued.pendingListed());
		});
	for (let i = 0; i < 4; i++) {
		watch();
		await s.issue();
		now += 1000;
	}
	// The fourth add found three of four: within a margin of one, so the session was listed first.
	expect(listedAtAdd).toEqual([[], [], [], [s.session.id]]);
	expect(await s.issued.pendingListed()).toEqual([s.session.id]);
});

it("refuses to start with a margin that is not below the cap", async () => {
	await expect(boot({ size: 4, margin: 4 })).rejects.toMatchObject({
		refusals: [{ where: "session-tokens.push-out-margin" }],
	});
});

it("revokes in the sweep what an add pushed out when the host stopped right after the add", async () => {
	const s = await boot({ size: 2 });
	const a = await s.issue();
	now += 1000;
	await s.issue();
	now += 1000;
	s.issued.stopAfterNextAdd();
	await expect(s.issue()).rejects.toThrow("the host stopped");
	expect((await s.t.verifyAccess(a.token)).kind).toBe("valid");
	await new Promise((resolve) => setTimeout(resolve, 1300));
	expect(await s.t.verifyAccess(a.token)).toEqual({ kind: "invalid", reason: "revoked" });
});

it("keeps a session listed while another add's push-out awaits, so the sweep revokes what that host left", async () => {
	const s = await boot({ size: 2, margin: 1 });
	const first = await s.issue();
	now += 1000;
	const second = await s.issue();
	now += 1000;
	// While this add settles what it pushed out, another pushes out the next, and its host stops.
	s.issued.beforeNextSettle(async () => {
		now += 1000;
		s.issued.stopAfterNextAdd();
		await expect(s.issue()).rejects.toThrow("the host stopped");
	});
	await s.issue();
	expect(await s.t.verifyAccess(first.token)).toEqual({ kind: "invalid", reason: "revoked" });
	expect(await s.issued.pendingListed()).toEqual([s.session.id]);
	await new Promise((resolve) => setTimeout(resolve, 1300));
	expect(await s.t.verifyAccess(second.token)).toEqual({ kind: "invalid", reason: "revoked" });
	expect(await s.issued.pendingListed()).toEqual([]);
});

it("warns when the sweep still cannot revoke a listed reference, and keeps it listed", async () => {
	const s = await boot({ size: 3 });
	await s.issue();
	now += 1;
	crowdNextAdd(s, 3);
	s.down.unavailable("revokeReferenced");
	await expect(s.issue()).rejects.toSatisfy(isUnavailable);
	await new Promise((resolve) => setTimeout(resolve, 1300));
	expect(loggedEvents()).toContain("session-tokens.revoke_retry_failed");
	expect(await s.issued.sets.awaiting(s.session.id)).toHaveLength(2);
	expect(await s.issued.pendingListed()).toEqual([s.session.id]);
	s.down.restore();
});

it("revokes every token the place pushes out, and keeps the record", async () => {
	const s = await boot({ size: 3 });
	const a = await s.issue();
	// A later expiry, in whole seconds, so the place pushes out `a` first.
	now += 1000;
	crowdNextAdd(s, 2);
	const b = await s.issue();
	expect(await s.t.verifyAccess(a.token)).toEqual({ kind: "invalid", reason: "revoked" });
	expect((await s.t.verifyAccess(b.token)).kind).toBe("valid");
	expect(await s.app.get(sessionTokens).sessionOf(b.id)).toEqual({
		kind: "bound",
		handle: s.session.id,
	});
});

it("leaves the session closing when tokens answers that it cannot revoke after all", async () => {
	const refusing = defineModule({ name: "tokens" }, (m) => [
		m.provide(tokens).by(
			() =>
				({
					revocable: () => true,
					revokeReferenced: async () => ({ kind: "unsupported" }),
				}) as unknown as Tokens,
		),
	]);
	const s = await boot({ tokens: refusing });
	await recording(s.app)(s.session.id, { id: "t", expiresAt: now + 60_000 });
	expect((await s.opened.close(s.session.id)).kind).toBe("pending");
});

it("fails the record at the first pushed-out token tokens cannot revoke, as closing does", async () => {
	const asked: string[] = [];
	const refusing = defineModule({ name: "tokens" }, (m) => [
		m.provide(tokens).by(
			() =>
				({
					revocable: () => true,
					revokeReferenced: async (reference: string) => {
						asked.push(reference);
						return { kind: "unsupported" };
					},
				}) as unknown as Tokens,
		),
	]);
	const s = await boot({ tokens: refusing, size: 3 });
	const record = recording(s.app);
	await record(s.session.id, { id: "t-1", expiresAt: now + 60_000 });
	crowdNextAdd(s, 3);
	await expect(record(s.session.id, { id: "t-2", expiresAt: now + 60_000 })).rejects.toSatisfy(
		isUnavailable,
	);
	expect(asked).toHaveLength(1);
	expect(await s.issued.sets.awaiting(s.session.id)).toHaveLength(2);
});

it("records a token token-endpoint tells of as issued from a session, so closing it revokes the token", async () => {
	const s = await boot();
	const token = await issuedAccess(s.t);
	const [one, ...more] = s.app.get(told);
	expect(more).toEqual([]);
	await one?.issued(s.session.id, { id: token.id, expiresAt: token.expiresAt });
	expect(await s.app.get(sessionTokens).sessionOf(token.id)).toEqual({
		kind: "bound",
		handle: s.session.id,
	});
	expect((await s.opened.close(s.session.id)).kind).toBe("closed");
	expect(await s.t.verifyAccess(token.token)).toEqual({ kind: "invalid", reason: "revoked" });
});

it("answers the session a recorded token was issued for, and unbound for any other", async () => {
	const s = await boot();
	const a = await s.issue();
	const other = await issuedAccess(s.t);
	const bound = s.app.get(sessionTokens);
	expect(await bound.sessionOf(a.id)).toEqual({ kind: "bound", handle: s.session.id });
	expect(await bound.sessionOf(other.id)).toEqual({ kind: "unbound" });
});

it("keeps a token bound to its session after the session closes", async () => {
	const s = await boot();
	const a = await s.issue();
	expect((await s.opened.close(s.session.id)).kind).toBe("closed");
	expect(await s.app.get(sessionTokens).sessionOf(a.id)).toEqual({
		kind: "bound",
		handle: s.session.id,
	});
});

it("keeps a token the place pushes out bound to its session", async () => {
	const s = await boot({ size: 3 });
	const recorded = [await s.issue()];
	crowdNextAdd(s, 2);
	const third = await issuedAccess(s.t);
	const bound = s.app.get(sessionTokens);
	await recording(s.app)(s.session.id, third);
	const all = [...recorded, third];
	const kept = (await s.issued.sets.members(s.session.id)).map((m) => m.member);
	expect(all.filter((token) => !kept.includes(referenceOf(token)))).toHaveLength(1);
	for (const token of all) {
		expect(await bound.sessionOf(token.id)).toEqual({ kind: "bound", handle: s.session.id });
	}
});

it("indexes a token before keeping it, so no kept token is missing from the index", async () => {
	const s = await boot();
	s.issued.down.unavailable("save");
	await expect(s.issue()).rejects.toSatisfy(isUnavailable);
	expect(await s.issued.sets.members(s.session.id)).toEqual([]);
});

it("refuses to record a token bound to another session, and keeps its first session", async () => {
	const s = await boot();
	const a = await s.issue();
	const bound = s.app.get(sessionTokens);
	const record = recording(s.app);
	await record(s.session.id, a);
	await expect(record("another", a)).rejects.toSatisfy(isUnavailable);
	expect(await s.issued.sets.members("another")).toEqual([]);
	expect(await bound.sessionOf(a.id)).toEqual({ kind: "bound", handle: s.session.id });
});

it("keeps a token's session for its remaining lifetime plus the allowance", async () => {
	const s = await boot();
	const a = await s.issue();
	const bound = s.app.get(sessionTokens);
	now = a.expiresAt + allowanceMs - 1;
	expect((await bound.sessionOf(a.id)).kind).toBe("bound");
	now += 1;
	expect(await bound.sessionOf(a.id)).toEqual({ kind: "unbound" });
});

it("throws unavailable, never unbound, when the index cannot tell", async () => {
	const s = await boot();
	const a = await s.issue();
	s.issued.down.unavailable("read");
	await expect(s.app.get(sessionTokens).sessionOf(a.id)).rejects.toSatisfy(isUnavailable);
});

it("sweeps every 30s unless set, taking a time only with its unit and in whole seconds", () => {
	const takes = (settings: object) => sessionTokensModule.section?.safeParse(settings).success;
	expect(sessionTokensModule.section?.parse({})).toEqual({
		"sweep-interval": 30,
		"push-out-margin": 8,
	});
	expect(
		[{ "sweep-interval": "1h" }, { "sweep-interval": 30 }, { "sweep-interval": "1500ms" }].map(
			takes,
		),
	).toEqual([true, false, false]);
});
