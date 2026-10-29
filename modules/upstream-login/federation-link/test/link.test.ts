import type { AuditRecord } from "@mod/audit";
import type { HttpRequest } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { AuthContext, Entry, Session } from "@mod/session";
import type { Joined } from "@mod/upstream-handoff";
import type { Continued, UpstreamLogin } from "@mod/upstreams";
import { expect, it } from "vitest";
import { linkWith } from "../src/link.ts";

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
function standIn(
	more: { readonly stepUp?: { readonly page: string; readonly origin: string } } = {},
) {
	const set = {
		sameOrigin: true,
		entry: { kind: "entered", session: s1, endsAt: 0 } as Entry,
		entered: s1 as Session | undefined,
		/** The entry the recorded session's handle answers. */
		byHandle: { kind: "entered", session: s1, endsAt: 0 } as Entry,
		linked: "linked" as "linked" | "already" | "conflict",
		/** What changes while the tokens join the session. */
		onJoin: undefined as (() => void) | undefined,
		/** What changes while the identity is linked. */
		onLink: undefined as (() => void) | undefined,
		unlinked: "unlinked" as "unlinked" | "none" | "fixed",
		/** The join throws, after what changes while it runs. */
		joinThrows: false,
		/** Taking the tokens back throws. */
		withdrawThrows: false,
		down: undefined as "users" | "entering" | "session" | "handoff" | undefined,
	};
	const levels: unknown[] = [];
	/** The handles the session was asked the entry of, with the level when one was named. */
	const asked: unknown[] = [];
	const events: AuditRecord[] = [];
	const links: unknown[] = [];
	const joined: unknown[] = [];
	const withdrawn: unknown[] = [];
	const unlinks: unknown[] = [];
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
				set.onLink?.();
				return set.linked;
			},
			unlink: async (subject, upstream) => {
				unlinks.push([subject, upstream]);
				return set.unlinked;
			},
		},
		audit: { record: (event) => void events.push(event) },
		handoff: {
			joined: async (session, idp, tokens) => {
				if (set.down === "handoff") throw new Unavailable("federation");
				set.onJoin?.();
				if (set.joinThrows) throw new Unavailable("federation");
				joined.push([session.id, idp, tokens.accessToken]);
				return `joined ${session.id} ${idp}` as unknown as Joined;
			},
			withdrawn: async (session, idp, given) => {
				if (set.withdrawThrows) throw new Unavailable("federation");
				withdrawn.push([session, idp, given]);
			},
		},
		log: logged.log,
		...(more.stepUp ? { stepUp: more.stepUp } : {}),
	});
	/** What this link's start kept. */
	const kept = { session: "s1", subject: "alice" };
	const completing = (more: Partial<Continued> = {}): Continued => ({
		request: testRequest(),
		idp: "corp",
		upstreamLogin,
		kept,
		lands: landing,
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
		unlinks,
		logged,
		link,
		kept,
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
		kept: { session: "s1", subject: "alice" },
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

it("names the step-up page a short start is sent to, with the requirement and only this start to come back to", async () => {
	const s = standIn({
		stepUp: { page: "https://as.example/raise?from=link", origin: "https://as.example" },
	});
	s.set.entry = { kind: "short", requirement: "mfa", answer: { error: "step_up_required" } };
	// The browser's own query goes nowhere: the start is spelled from the origin and its path alone.
	const request = testRequest({
		path: "/session/oauth/federation/corp",
		query: new Map([
			["link", ["1"]],
			["redirect_to", ["https://evil.example/"]],
		]),
	});
	const [status, body] = (await refusedAt(s, request)) as [number, unknown];
	expect(status).toBe(403);
	const { page, ...rest } = body as { page: string };
	expect(rest).toEqual({ error: "step_up_required", requirement: "mfa" });
	const sent = new URL(page);
	expect(`${sent.origin}${sent.pathname}`).toBe("https://as.example/raise");
	expect([...sent.searchParams]).toEqual([
		["from", "link"],
		["requirement", "mfa"],
		["redirect_to", "https://as.example/session/oauth/federation/corp?link=1"],
	]);
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

it("links the identity to the session's subject, hands the tokens to that session, records it, and lands by 303 [rfc9700-4.12-a]", async () => {
	const s = standIn();
	const done = await s.link.complete(s.completing());
	expect([done.status, done.headers?.location, done.cookies]).toEqual([
		303,
		landing,
		["federation.corp=; Max-Age=0"],
	]);
	expect(s.links).toEqual([["alice", { idp: "corp", subject: "u-1" }]]);
	expect(s.joined).toEqual([["s1", "corp", "up-1"]]);
	// The recorded session, at credentials as its start was: before the link, after it, and after the join.
	expect(s.asked).toEqual([
		["s1", "credentials"],
		["s1", "credentials"],
		["s1", "credentials"],
	]);
	expect(s.unlinks).toEqual([]);
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
	expect((await s.link.complete(s.completing())).status).toBe(303);
	expect(s.links).toHaveLength(1);
});

it("lands where the round trip says, and hands nothing on when the upstream gave no tokens", async () => {
	const s = standIn();
	const { tokens: _, ...tokenless } = upstreamLogin;
	const done = await s.link.complete(
		s.completing({
			lands: "https://app.example/back",
			upstreamLogin: tokenless,
		}),
	);
	expect(done.headers?.location).toBe("https://app.example/back");
	expect(s.joined).toEqual([]);
});

it("takes an identity the account holds already without a record, and refuses another account's, handing nothing on", async () => {
	const s = standIn();
	s.set.linked = "already";
	expect((await s.link.complete(s.completing())).status).toBe(303);
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

const upstream = { idp: "corp", subject: "u-1" };
const undone = ["federation.identity.linked", "federation.identity.link_refused"];

it("undoes a link it wrote, and takes the tokens back, when the session closed, fell short or changed hands meanwhile: 401", async () => {
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
	for (const [change, apply] of Object.entries(changes)) {
		for (const during of ["onJoin", "onLink"] as const) {
			const s = standIn();
			s.set[during] = () => apply(s.set);
			const done = await s.link.complete(s.completing());
			expect([...answered(done), done.cookies], change).toEqual([
				401,
				{ error: "login_required" },
				["federation.corp=; Max-Age=0"],
			]);
			// Checked right after the link, the tokens are never handed to a session closed by then.
			const handed = during === "onJoin" ? [["s1", "corp", "joined s1 corp"]] : [];
			expect([s.unlinks, s.withdrawn], change).toEqual([[["alice", upstream]], handed]);
			expect(s.joined.length, change).toBe(handed.length);
			expect(
				s.events.map((e) => [e.kind, e.attributes?.reason]),
				change,
			).toEqual([
				[undone[0], undefined],
				[undone[1], "session_closed_during_link"],
			]);
		}
	}
});

it("undoes no link the account held already, and no tokens it was not given, when the session closed meanwhile", async () => {
	const s = standIn();
	s.set.linked = "already";
	const { tokens: _, ...tokenless } = upstreamLogin;
	s.set.onLink = () => {
		s.set.byHandle = { kind: "absent" };
	};
	expect(answered(await s.link.complete(s.completing({ upstreamLogin: tokenless })))).toEqual([
		401,
		{ error: "login_required" },
	]);
	expect([s.unlinks, s.withdrawn]).toEqual([[], []]);
	expect(s.events.map((e) => e.attributes?.reason)).toEqual(["session_closed_during_link"]);
});

it("undoes the link when the join fails while the session is closed or cannot be read, and keeps it while it is open", async () => {
	const closings: Record<string, (set: Settings) => void> = {
		closed: (set) => {
			set.byHandle = { kind: "absent" };
		},
		unreadable: (set) => {
			set.down = "session";
		},
		open: () => {},
	};
	for (const [closing, apply] of Object.entries(closings)) {
		const s = standIn();
		s.set.joinThrows = true;
		s.set.onJoin = () => apply(s.set);
		await expect(s.link.complete(s.completing()), closing).rejects.toSatisfy(isUnavailable);
		expect(s.unlinks, closing).toEqual(closing === "open" ? [] : [["alice", upstream]]);
		expect(s.withdrawn, closing).toEqual([]);
	}
});

it("unlinks even where taking the tokens back fails, then fails with that", async () => {
	const s = standIn();
	s.set.withdrawThrows = true;
	s.set.onJoin = () => {
		s.set.byHandle = { kind: "absent" };
	};
	await expect(s.link.complete(s.completing())).rejects.toSatisfy(isUnavailable);
	expect(s.unlinks).toEqual([["alice", upstream]]);
});

it("logs a link it cannot undo, as one the configuration fixes", async () => {
	const s = standIn();
	s.set.unlinked = "fixed";
	s.set.onLink = () => {
		s.set.byHandle = { kind: "absent" };
	};
	expect((await s.link.complete(s.completing())).status).toBe(401);
	expect(s.logged.lines().map((line) => [line.level, line.event])).toContainEqual([
		"warn",
		"federation.link_kept_fixed",
	]);
});

it("undoes the link and takes the tokens back before failing as unavailable when the session cannot tell after them", async () => {
	const s = standIn();
	s.set.onJoin = () => {
		s.set.down = "session";
	};
	await expect(s.link.complete(s.completing())).rejects.toSatisfy(isUnavailable);
	expect([s.links.length, s.unlinks, s.withdrawn]).toEqual([
		1,
		[["alice", upstream]],
		[["s1", "corp", "joined s1 corp"]],
	]);
	expect(s.events.map((e) => e.kind)).toEqual(["federation.identity.linked"]);
});

it("records a refusal after the take for the subject its start kept, and nothing for what it cannot read", () => {
	const s = standIn();
	const at = { idp: "corp", reason: "exchange_failed", source: "127.0.0.1", userAgent: "ua/1" };
	s.link.failed({ ...at, kept: s.kept });
	s.link.failed({ ...at, kept: undefined });
	s.link.failed({ ...at, kept: { unheard: 1 } });
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
