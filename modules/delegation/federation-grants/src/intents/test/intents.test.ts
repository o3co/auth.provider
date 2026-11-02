import { describe, expect, it } from "vitest";
import { back, intents, origin, scopes, upstreamTokens } from "./harness.ts";

const upstream = { issuer: "https://up.example", subject: "u-alice" };
const outcomes = (h: Awaited<ReturnType<typeof intents>>, kind: string) =>
	h.events.filter((e) => e.kind === kind).map((e) => e.attributes);

describe("the link and the question", () => {
	it("reads a live link's intent without spending it, and refuses another step, an ended intent or one past its time", async () => {
		const h = await intents();
		const { link } = await h.lodge();
		const first = await h.linked(link);
		expect(first.view).toEqual({ subject: "alice", client: "worker", connection: "cal" });
		// A login or a step-up comes back to the same link.
		expect((await h.intents.linked(link)).kind).toBe("linked");
		const late = await h.lodge({ endsAt: h.now() });
		expect((await h.intents.linked(late.link)).kind).toBe("stale");
		const { challenge } = await h.questioned();
		expect((await h.intents.linked(challenge)).kind).toBe("stale");
		expect(h.intents.connected).toBe(true);
		expect(h.intents.callbackOf("/session/federation-grants/callback/cal")).toBe("cal");
		for (const path of [
			"/session/federation-grants/callback/Cal",
			"/session/federation-grants/callback/a/b",
			"/elsewhere/callback/cal",
		])
			expect(h.intents.callbackOf(path), path).toBeUndefined();
		expect((await intents({ settings: { connections: {} } })).intents.connected).toBe(false);
		expect(h.intents.connectUrl("abc")).toBe(
			`${origin}/session/federation-grants/connect?request=abc`,
		);
	});

	it("says whether the client may still use the connection, and the connection is still there", async () => {
		const h = await intents();
		const { ref } = await h.linked((await h.lodge()).link);
		expect(await h.intents.available(ref)).toBe(true);
		expect(await h.intents.permitted(ref)).toBe(true);
		h.relist([], [back]);
		expect(await h.intents.available(ref)).toBe(false);
		expect(await h.intents.permitted(ref)).toBe(false);
		h.relist(["cal"], [back]);
		// A connection taken out of the settings: still permitted to the client, no longer available.
		const gone = await intents({ settings: { connections: {} } });
		const other = await gone.linked((await gone.lodge()).link);
		expect(await gone.intents.available(other.ref)).toBe(false);
		expect(await gone.intents.permitted(other.ref)).toBe(true);
	});

	it("binds the intent to the first session, makes a question for it, and leaves another session stale", async () => {
		const h = await intents();
		const { link } = await h.lodge();
		const { ref } = await h.linked(link);
		const bound = await h.intents.bound(ref, "s-1");
		expect(bound.kind).toBe("bound");
		expect(
			(await h.intents.linked(link)).kind === "linked" && (await h.linked(link)).view.session,
		).toBe("s-1");
		const again = await h.linked(link);
		expect((await h.intents.bound(again.ref, "s-2")).kind).toBe("stale");
		// The same session takes it again, with a question of its own.
		expect((await h.intents.bound(again.ref, "s-1")).kind).toBe("bound");
	});

	it("asks a question without spending it, and answers what the user is asked", async () => {
		const h = await intents();
		const { challenge } = await h.questioned();
		const asked = await h.intents.asked(challenge);
		expect(asked.kind === "asked" && asked.view).toEqual({
			subject: "alice",
			client: "worker",
			connection: "cal",
			scopes,
			grantLifetimeMs: 30 * 86_400_000,
			expiresInMs: 600_000,
			session: "s-1",
		});
		expect((await h.intents.asked(challenge)).kind).toBe("asked");
		expect((await h.intents.asked("no-such")).kind).toBe("invalid");
	});
});

describe("raising the session", () => {
	it("marks one trip per requirement and login, true only for the request that marked it", async () => {
		const h = await intents();
		const { link } = await h.lodge();
		expect(await h.intents.steppedUp((await h.linked(link)).ref, "mfa", h.now())).toBe(true);
		expect(await h.intents.steppedUp((await h.linked(link)).ref, "mfa", h.now())).toBe(false);
		expect(await h.intents.steppedUp((await h.linked(link)).ref, "email", h.now())).toBe(true);
		h.advance(1000);
		expect(await h.intents.steppedUp((await h.linked(link)).ref, "email", h.now())).toBe(true);
	});

	it("changes no intent past its time since it was read: no session is bound and no trip marked", async () => {
		const h = await intents();
		const { link } = await h.lodge({ endsAt: h.now() + 1000 });
		const { ref } = await h.linked(link);
		h.advance(1000);
		expect((await h.intents.bound(ref, "s-1")).kind).toBe("stale");
		expect(await h.intents.steppedUp(ref, "mfa", h.now())).toBe(false);
		// Back within its time, the intent reads as it was: unbound, and no trip marked.
		h.advance(-1000);
		expect((await h.linked(link)).view.session).toBeUndefined();
		expect(await h.intents.steppedUp(ref, "mfa", h.now())).toBe(true);
	});

	it("answers false where another request marked the trip first, or the intent was replaced", async () => {
		for (const raced of [
			{ stepped: { requirement: "mfa", at: 1_800_000_000_000 } },
			{ id: "another-intent", stepped: undefined },
		] as const) {
			const h = await intents();
			const { ref } = await h.linked((await h.lodge()).link);
			h.meanwhile({}, raced);
			expect(await h.intents.steppedUp(ref, "mfa", h.now()), JSON.stringify(raced)).toBe(false);
		}
	});
});

describe("the decision", () => {
	it("spends a denied question, ends the intent as denied, audits it with its source, and answers the way back", async () => {
		const h = await intents();
		const { id, ref, challenge } = await h.questioned();
		const denied = await h.intents.denied(ref, challenge, { source: "203.0.113.9" });
		expect(denied.kind === "back" && new URL(denied.location).searchParams.get("error")).toBe(
			"access_denied",
		);
		expect(h.grantOf(id)?.intent?.ended).toBe("access_denied");
		expect(outcomes(h, "federation.grant.authorization_failed")).toEqual([
			{ client: "worker", connection: "cal", outcome: "access_denied", source: "203.0.113.9" },
		]);
		expect((await h.intents.denied(ref, challenge, {})).kind).toBe("invalid");
	});

	it("denies over the intent already read: one replaced since still spends the question, audits and goes back", async () => {
		const h = await intents();
		const { id, ref, challenge } = await h.questioned();
		await h.stores.grants.change(id, (record) => {
			const r = record as unknown as { intent: object };
			return { value: { ...r, intent: { ...r.intent, id: "another-intent" } } as never };
		});
		const denied = await h.intents.denied(ref, challenge, {});
		expect(denied.kind === "back" && new URL(denied.location).searchParams.get("error")).toBe(
			"access_denied",
		);
		expect(h.grantOf(id)?.intent).toMatchObject({ id: "another-intent" });
		expect(h.grantOf(id)?.intent?.ended).toBeUndefined();
		expect(outcomes(h, "federation.grant.authorization_failed")).toEqual([
			{ client: "worker", connection: "cal", outcome: "access_denied" },
		]);
		expect((await h.intents.asked(challenge)).kind).toBe("invalid");
	});

	it("gives a start's parts without spending the question, and spends it once on acceptance", async () => {
		const h = await intents();
		const { id, challenge } = await h.questioned();
		// The decision reads the question's intent, bound to the session that took it.
		const asked = await h.intents.asked(challenge);
		if (asked.kind !== "asked") throw new Error("not asked");
		const { ref } = asked;
		const start = h.intents.starting(ref);
		expect(start).toMatchObject({
			carried: { grant: id, intent: expect.any(String), session: "s-1" },
			idp: "corp",
			redirectUri: `${origin}/session/federation-grants/callback/cal`,
			scopes,
		});
		expect((await h.intents.asked(challenge)).kind).toBe("asked");
		expect(await h.intents.accepted(challenge)).toBe(true);
		expect(await h.intents.accepted(challenge)).toBe(false);
		expect((await h.intents.asked(challenge)).kind).toBe("invalid");
		h.withdraw();
		expect(h.intents.starting(ref)).toBeUndefined();
	});
});

describe("the callback", () => {
	it("resumes a live intent by what its round trip carried, and tells an unconfigured connection apart", async () => {
		const h = await intents();
		const { id, link } = await h.lodge({ expectedUpstream: "u-alice" });
		const { ref } = await h.linked(link);
		await h.intents.bound(ref, "s-1");
		const carried = h.intents.starting((await h.linked(link)).ref)?.carried;
		const resumed = await h.intents.resumed(carried);
		expect(resumed.kind === "resumed" && resumed.view).toMatchObject({
			subject: "alice",
			connection: "cal",
			idp: "corp",
			expected: { subject: "u-alice" },
			scopes,
			session: "s-1",
		});
		expect((await h.intents.resumed({ ...carried, intent: "other" })).kind).toBe("stale");
		expect((await h.intents.resumed("garbage")).kind).toBe("stale");
		h.withdraw();
		expect((await h.intents.resumed(carried)).kind).toBe("unconfigured");
		expect(h.grantOf(id)?.status).toBe("pending");
	});

	it("tells the intent revoked once its subject is revoked since it started", async () => {
		const h = await intents();
		const { ref } = await h.linked((await h.lodge()).link);
		expect(await h.intents.stillValid(ref)).toBeUndefined();
		h.advance(2000);
		await h.revoke();
		expect(await h.intents.stillValid(ref)).toBe("access_denied");
	});

	it("activates over its own intent, seals the credentials, audits it with the check and source, and goes back", async () => {
		const h = await intents();
		const { id, ref } = await h.questioned();
		const done = await h.intents.activated(ref, {
			upstream,
			tokens: h.held(ref, upstreamTokens()),
			identityCheck: "required",
			source: "203.0.113.9",
		});
		expect(done.kind === "back" && new URL(done.location).searchParams.get("grant_id")).toBe(id);
		const grant = h.grantOf(id);
		expect(grant).toMatchObject({ status: "active", upstream, intent: { ended: "connected" } });
		expect(grant?.sealed).toEqual(expect.any(String));
		expect(outcomes(h, "federation.grant.authorized")).toEqual([
			{ client: "worker", connection: "cal", outcome: "required", source: "203.0.113.9" },
		]);
	});

	it("refuses tokens not to hold without ending the intent, ends it where a race took it, and writes no credentials", async () => {
		const h = await intents();
		const refused = await h.questioned();
		// Judged apart, before the last check, and writing nothing: the browser half ends the intent.
		expect(h.intents.judged(refused.ref, upstreamTokens({ refreshToken: undefined }))).toEqual({
			kind: "refused",
			why: "refresh_token_absent",
		});
		expect(h.grantOf(refused.id)?.status).toBe("pending");
		expect(h.grantOf(refused.id)?.intent?.ended).toBeUndefined();
		expect(h.grantOf(refused.id)?.sealed).toBeUndefined();
		const gone = await intents({ settings: { connections: {} } });
		const other = await gone.linked((await gone.lodge()).link);
		expect(gone.intents.judged(other.ref, upstreamTokens())).toEqual({
			kind: "refused",
			why: "grant_not_authorizable",
		});
		const raced = await h.questioned("s-2");
		h.meanwhile({}, { id: "another-intent" });
		const lost = await h.intents.activated(raced.ref, {
			upstream,
			tokens: h.held(raced.ref, upstreamTokens()),
			identityCheck: "required",
		});
		expect(lost.kind === "back" && new URL(lost.location).searchParams.get("error")).toBe(
			"grant_not_authorizable",
		);
		expect(h.grantOf(raced.id)?.status).toBe("pending");
		// An intent ended meanwhile, as by a denial in another tab, is not activated after all.
		const ended = await h.questioned("s-3");
		h.meanwhile({}, { ended: "access_denied" });
		const late = await h.intents.activated(ended.ref, {
			upstream,
			tokens: h.held(ended.ref, upstreamTokens()),
			identityCheck: "required",
		});
		expect(late.kind === "back" && new URL(late.location).searchParams.get("error")).toBe(
			"grant_not_authorizable",
		);
		expect(h.grantOf(ended.id)).toMatchObject({
			status: "pending",
			intent: { ended: "access_denied" },
		});
		expect(h.grantOf(ended.id)?.sealed).toBeUndefined();
	});
});

describe("failures and notes", () => {
	it("ends with an error and an outcome of its own, and answers stale where the client no longer lists the return", async () => {
		const h = await intents();
		const { id, ref } = await h.questioned();
		h.relist(["cal"], []);
		const failed = await h.intents.failed(ref, "grant_not_authorizable", {
			outcome: "upstream_refused_start",
		});
		expect(failed.kind).toBe("stale");
		expect(h.grantOf(id)?.intent?.ended).toBe("grant_not_authorizable");
		expect(outcomes(h, "federation.grant.authorization_failed")).toEqual([
			{ client: "worker", connection: "cal", outcome: "upstream_refused_start" },
		]);
	});

	it("audits a refusal that leaves the intent as it is, and a step whose grant is unknown", async () => {
		const h = await intents();
		const { id, ref } = await h.questioned();
		h.intents.noted(ref, "reauthentication_required", { source: "203.0.113.9" });
		h.intents.unanswered({});
		expect(h.grantOf(id)?.intent?.ended).toBeUndefined();
		expect(outcomes(h, "federation.grant.authorization_failed")).toEqual([
			{
				client: "worker",
				connection: "cal",
				outcome: "reauthentication_required",
				source: "203.0.113.9",
			},
			{ outcome: "unavailable" },
		]);
	});
});
