import type { AuditRecord } from "@mod/audit";
import type { HttpRequest } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { AuthContext, Entry, Session } from "@mod/session";
import type { UpstreamLogin } from "@mod/upstreams";
import { expect, it } from "vitest";
import type { Completing, Idp } from "../../round-trip/round-trip.ts";
import type { Transaction } from "../../round-trip/transaction.ts";
import { linkWith } from "../link.ts";

const alice: AuthContext = { subject: "alice", amr: ["pwd"], authenticatedAt: 0 };
const s1: Session = { id: "s1", context: alice };
const landing = "https://app.example/home";
const upstreamLogin: UpstreamLogin = {
	subject: "u-1",
	amr: [],
	tokens: { accessToken: "up-1", tokenType: "Bearer", scope: [] },
};

/** The link over stand-ins a test sets: by default the browser is still in the session it started from. */
type Settings = ReturnType<typeof standIn>["set"];
function standIn() {
	const set = {
		sameOrigin: true,
		entry: { kind: "entered", session: s1, endsAt: 0 } as Entry,
		entered: s1 as Session | undefined,
		/** The entry the recorded session's handle answers. */
		byHandle: { kind: "entered", session: s1, endsAt: 0 } as Entry,
		linked: "linked" as "linked" | "already" | "conflict",
		/** What changes while the tokens join the session. */
		onJoin: undefined as (() => void) | undefined,
		down: undefined as "users" | "entering" | "session" | "handoff" | undefined,
	};
	const levels: unknown[] = [];
	/** The handles the session was asked the entry of, with the level when one was named. */
	const asked: unknown[] = [];
	const events: AuditRecord[] = [];
	const links: unknown[] = [];
	const joined: unknown[] = [];
	const withdrawn: unknown[] = [];
	const logged = recordingLog();
	const link = linkWith({
		origin: { sameOrigin: () => set.sameOrigin },
		sessions: {
			enterFor: async (_request, level) => {
				levels.push(level);
				return set.entry;
			},
			enter: async () => {
				if (set.down === "entering") throw new Unavailable("session");
				return set.entered;
			},
			entryOf: async (handle, level) => {
				if (set.down === "session") throw new Unavailable("session");
				asked.push(level === undefined ? handle : [handle, level]);
				return set.byHandle;
			},
		},
		users: {
			link: async (subject, upstream) => {
				if (set.down === "users") throw new Unavailable("users");
				links.push([subject, upstream]);
				return set.linked;
			},
		},
		audit: { record: (event) => void events.push(event) },
		handoff: {
			joined: async (session, idp, tokens) => {
				if (set.down === "handoff") throw new Unavailable("federation");
				joined.push([session.id, idp, tokens.accessToken]);
				set.onJoin?.();
			},
			withdrawn: async (session, idp) => void withdrawn.push([session, idp]),
		},
		log: logged.log,
		landing,
	});
	const transaction: Transaction = {
		format: 1,
		idp: "corp",
		state: "st",
		nonce: "n",
		verifier: "v",
		startedAt: 0,
		link: { session: "s1", subject: "alice" },
	};
	const completing = (more: Partial<Completing> = {}): Completing => ({
		request: testRequest(),
		name: "corp",
		idp: { upstreamAmr: new Map() } as Pick<Idp, "upstreamAmr"> as Idp,
		upstreamLogin,
		transaction,
		source: "127.0.0.1",
		userAgent: "ua/1",
		cleared: ["federation.corp=; Max-Age=0"],
		...more,
	});
	return {
		set,
		levels,
		asked,
		events,
		links,
		joined,
		withdrawn,
		logged,
		link,
		transaction,
		completing,
	};
}
/** What a start or a callback answered: its status and its JSON. */
const answered = (response: { status: number; body?: unknown }) => [
	response.status,
	(response.body as { json?: unknown } | undefined)?.json,
];
const refusedAt = async (s: ReturnType<typeof standIn>, request: HttpRequest = testRequest()) => {
	const begun = await s.link.begin(request, "corp");
	return "answer" in begun ? answered(begun.answer) : begun;
};

it("starts only for a session entered at the credentials level, recording it and its subject", async () => {
	const s = standIn();
	expect(await s.link.begin(testRequest(), "corp")).toEqual({
		carried: { link: { session: "s1", subject: "alice" } },
	});
	expect(s.levels).toEqual(["credentials"]);
	s.set.entry = { kind: "absent" };
	expect(await refusedAt(s)).toEqual([401, { error: "login_required" }]);
});

it("answers a start a session requirement holds with its answer and the requirement's name", async () => {
	const s = standIn();
	s.set.entry = { kind: "short", requirement: "mfa", answer: { error: "step_up_required" } };
	expect(await refusedAt(s)).toEqual([403, { error: "step_up_required", requirement: "mfa" }]);
});

it("refuses a start not shown to come from this origin, logging the IdP and what the browser said", async () => {
	const s = standIn();
	s.set.sameOrigin = false;
	const request = testRequest({ headers: new Map([["sec-fetch-site", "cross-site\u0007"]]) });
	expect(await refusedAt(s, request)).toEqual([403, { error: "link_requires_trusted_origin" }]);
	expect(s.logged.lines()).toEqual([
		{
			level: "warn",
			event: "federation.link_start_rejected",
			fields: { idp: "corp", secFetchSite: "cross-site" },
		},
	]);
});

it("links the identity to the session's subject, hands the tokens to that session, and records it", async () => {
	const s = standIn();
	const done = await s.link.complete(s.completing());
	expect([done.status, done.headers?.location, done.cookies]).toEqual([
		302,
		landing,
		["federation.corp=; Max-Age=0"],
	]);
	expect(s.links).toEqual([["alice", { idp: "corp", subject: "u-1" }]]);
	expect(s.joined).toEqual([["s1", "corp", "up-1"]]);
	// The recorded session, at use, before the link and again after the join.
	expect(s.asked).toEqual(["s1", "s1"]);
	expect(s.events).toEqual([
		{
			kind: "federation.identity.linked",
			subject: "alice",
			attributes: { idp: "corp", source: "127.0.0.1", userAgent: "ua/1" },
		},
	]);
});

it("lets the recorded session decide for a browser in none, as a posted answer carries no cookie", async () => {
	const s = standIn();
	s.set.entered = undefined;
	expect((await s.link.complete(s.completing())).status).toBe(302);
	expect(s.links).toHaveLength(1);
});

it("returns to the target the start named, and hands nothing on when the upstream gave no tokens", async () => {
	const s = standIn();
	const { tokens: _, ...tokenless } = upstreamLogin;
	const done = await s.link.complete(
		s.completing({
			transaction: { ...s.transaction, redirectTo: "https://app.example/back" },
			upstreamLogin: tokenless,
		}),
	);
	expect(done.headers?.location).toBe("https://app.example/back");
	expect(s.joined).toEqual([]);
});

it("takes an identity the account holds already without a record, and refuses another account's, handing nothing on", async () => {
	const s = standIn();
	s.set.linked = "already";
	expect((await s.link.complete(s.completing())).status).toBe(302);
	expect(s.events).toEqual([]);
	expect(s.joined).toEqual([["s1", "corp", "up-1"]]);
	s.joined.length = 0;
	s.set.linked = "conflict";
	expect(answered(await s.link.complete(s.completing()))).toEqual([
		409,
		{ error: "identity_conflict" },
	]);
	expect(s.joined).toEqual([]);
	expect(s.events.map((e) => [e.kind, e.attributes?.reason])).toEqual([
		["federation.identity.link_refused", "conflict"],
	]);
});

const short: Entry = { kind: "short", requirement: "mfa", answer: { error: "step_up_required" } };
const enteredAs = (subject: string): Entry => ({
	kind: "entered",
	session: { id: "s1", context: { ...alice, subject } },
	endsAt: 0,
});

it("links nothing once the browser is in another session, or its session closed, fell short of a requirement or changed hands", async () => {
	const changes: Record<string, [(set: Settings) => void, string]> = {
		another: [
			(set) => {
				set.entered = { id: "s2", context: alice };
			},
			"login_required",
		],
		closed: [
			(set) => {
				set.byHandle = { kind: "absent" };
			},
			"login_required",
		],
		// Answered as closed; recorded with its own reason.
		short: [
			(set) => {
				set.byHandle = short;
			},
			"session_short",
		],
		subject: [
			(set) => {
				set.byHandle = enteredAs("bob");
			},
			"login_required",
		],
	};
	for (const [change, [apply, reason]] of Object.entries(changes)) {
		const s = standIn();
		apply(s.set);
		expect(answered(await s.link.complete(s.completing())), change).toEqual([
			401,
			{ error: "login_required" },
		]);
		expect([s.links, s.joined], change).toEqual([[], []]);
		expect(
			s.events.map((e) => [e.kind, e.attributes?.reason]),
			change,
		).toEqual([["federation.identity.link_refused", reason]]);
	}
});

it("fails as unavailable when users or the session cannot tell, recording nothing", async () => {
	for (const down of ["users", "entering", "session"] as const) {
		const s = standIn();
		s.set.down = down;
		await expect(s.link.complete(s.completing()), down).rejects.toSatisfy(isUnavailable);
		expect([s.events, s.joined], down).toEqual([[], []]);
	}
});

it("fails as unavailable when the tokens cannot be handed over, the link and its record kept", async () => {
	const s = standIn();
	s.set.down = "handoff";
	await expect(s.link.complete(s.completing())).rejects.toSatisfy(isUnavailable);
	expect(s.links).toHaveLength(1);
	expect(s.events.map((e) => e.kind)).toEqual(["federation.identity.linked"]);
});

it("answers a session closed, short of a requirement or logged in as someone else while joining as one before: 401, the link and its record kept, the tokens taken back", async () => {
	const changes: Record<string, (set: Settings) => void> = {
		closed: (set) => {
			set.byHandle = { kind: "absent" };
		},
		short: (set) => {
			set.byHandle = short;
		},
		subject: (set) => {
			set.byHandle = enteredAs("bob");
		},
	};
	for (const [change, onJoin] of Object.entries(changes)) {
		const s = standIn();
		s.set.onJoin = () => onJoin(s.set);
		const done = await s.link.complete(s.completing());
		expect([...answered(done), done.cookies], change).toEqual([
			401,
			{ error: "login_required" },
			["federation.corp=; Max-Age=0"],
		]);
		expect([s.links.length, s.joined, s.withdrawn], change).toEqual([
			1,
			[["s1", "corp", "up-1"]],
			[["s1", "corp"]],
		]);
		expect(
			s.events.map((e) => e.kind),
			change,
		).toEqual(["federation.identity.linked"]);
	}
});

it("takes the tokens back before failing as unavailable when the session cannot tell after the join", async () => {
	const s = standIn();
	s.set.onJoin = () => {
		s.set.down = "session";
	};
	await expect(s.link.complete(s.completing())).rejects.toSatisfy(isUnavailable);
	expect([s.links.length, s.joined, s.withdrawn]).toEqual([
		1,
		[["s1", "corp", "up-1"]],
		[["s1", "corp"]],
	]);
	expect(s.events.map((e) => e.kind)).toEqual(["federation.identity.linked"]);
});

it("records a refusal after the take for the subject a link started for, and nothing for a login's", () => {
	const s = standIn();
	const at = { name: "corp", reason: "exchange_failed", source: "127.0.0.1", userAgent: "ua/1" };
	s.link.failed({ ...at, transaction: s.transaction });
	const { link: _, ...login } = s.transaction;
	s.link.failed({ ...at, transaction: login });
	expect(s.events).toEqual([
		{
			kind: "federation.identity.link_refused",
			subject: "alice",
			attributes: {
				idp: "corp",
				source: "127.0.0.1",
				userAgent: "ua/1",
				reason: "exchange_failed",
			},
		},
	]);
});
