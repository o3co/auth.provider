import { randomBytes } from "node:crypto";
import {
	confirmation,
	type Deployed,
	type Instance,
	instanceOf,
	ready,
	replicasOnline,
	sameMark,
	successes,
} from "@mod/conformance/testing";
import type { ClientScene } from "@mod/conformance-oauth";
import { describe, expect, it } from "vitest";
import {
	app,
	type Code,
	callback,
	codeNoted,
	faultScene,
	issuer,
	on,
	pkce,
	redeemAt,
	refreshAt,
	rotationFrom,
	said,
} from "../../faults/test/faults.ts";
import {
	boundaryCreated,
	boundaryOf,
	closingAdded,
	isStoreOperation,
} from "../../faults/test/wire.ts";
import { backChannel, browserAt } from "../../testing.ts";

// Each scene reads what was made before a subject's boundary while the revocation's followers are held
// at their first write, so the subject's sessions are not closed nor their tokens revoked: what refuses
// is the boundary alone. Followers run one at a time (subject-revocation's followers.ts), and the first
// write held is session-lifecycle's, so every follower after it is held too; one contributed before it
// that revokes what these scenes read would make them rest on it, and `unfollowed` would not see it. A read after the followers' cleanup proves nothing of the boundary and is not
// taken as such. The scenes keep `tokens.subject-check` at its default; its exception (`none`) is not
// checked here.

const credential = randomBytes(32).toString("base64url");
const api = "https://api.example";
/** The client that asks a session grant for a browser's session. */
const bff: ClientScene = {
	id: "bff",
	kind: "confidential",
	method: "client_secret_post",
	secret: "bff-secret-0123456789abcdef",
	grants: ["session"],
	scopes: ["read"],
	defaultScopes: [],
	audiences: [api],
};
const users = {
	alice: { username: "alice", password: "alice-horse-battery-staple", subject: "user-alice" },
	bob: { username: "bob", password: "bob-horse-battery-staple", subject: "user-bob" },
	carol: { username: "carol", password: "carol-horse-battery-staple", subject: "user-carol" },
};
type User = (typeof users)[keyof typeof users];
/** The code flow's client, also seeing the API's tokens: introspection answers active only to a caller that may see a token's audience. */
const seeing: ClientScene = { ...app, scopes: ["openid", "read"], audiences: [api] };
const scene = faultScene({
	clients: [seeing, bff],
	users: Object.values(users).map((u) => ({
		identifier: u.username,
		password: u.password,
		subject: u.subject,
	})),
	refresh: {},
	sessionGrant: true,
	introspection: true,
	revocations: { credential, sources: ["198.51.100.0/24"] },
});

/** A form posted as a client, with the browser's cookie where it is the browser's own request. */
async function postAs(
	i: Instance,
	path: string,
	as: ClientScene,
	form: Record<string, string>,
	cookie = "",
) {
	const res = await fetch(`${i.baseUrl}${path}`, {
		method: "POST",
		headers: {
			...backChannel,
			"content-type": "application/x-www-form-urlencoded",
			...(cookie ? { cookie, origin: issuer, "x-forwarded-host": new URL(issuer).host } : {}),
		},
		body: new URLSearchParams({ ...form, client_id: as.id, client_secret: as.secret ?? "" }),
	});
	const text = await res.text();
	let body: Record<string, unknown> = {};
	try {
		body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {}
	return { status: res.status, body };
}
const sessionGrantAt = (i: Instance, cookie: string) =>
	postAs(i, "/oauth/token", bff, { grant_type: "session", scope: "read" }, cookie);
const activeAt = async (i: Instance, token: string) =>
	(await postAs(i, "/oauth/introspect", app, { token })).body.active;

/** The ledger's revocation of a subject at the instance, from its block over https, as its proxy forwards it. */
async function revokeAt(i: Instance, subject: string) {
	const res = await fetch(`${i.baseUrl}/ledger/subject-revocations`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "198.51.100.30",
			authorization: `Bearer ${credential}`,
		},
		body: JSON.stringify({ subject }),
	});
	const text = await res.text();
	let body: Record<string, unknown> = {};
	try {
		body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {}
	return { status: res.status, body };
}
const complete = { status: 200, body: { complete: true } };
const incomplete = { status: 503, error: "temporarily_unavailable", state: "incomplete" };
const unknown = { status: 503, error: "temporarily_unavailable", state: "unknown" };
const answered = (a: Awaited<ReturnType<typeof revokeAt>>) => ({
	status: a.status,
	error: a.body.error,
	state: a.body.state,
});

/** What a user's login made: its session, a code not yet redeemed, the tokens of another, and a session grant's token. */
interface Made {
	readonly user: User;
	/** Where the browser's requests go; a scene moves it to read at another instance. */
	readonly place: { i: Instance };
	readonly browser: ReturnType<typeof browserAt>;
	readonly cookie: string;
	readonly code: Code;
	readonly access: string;
	readonly refresh: string;
	readonly sessionToken: string;
}

/** A code the browser is given for the API as well as the user, its verifier of its own. */
async function codeFor(browser: ReturnType<typeof browserAt>): Promise<Code> {
	const { verifier, challenge } = pkce();
	const res = await browser.authorize({
		response_type: "code",
		client_id: app.id,
		redirect_uri: callback,
		state: "s1",
		scope: "openid read",
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	const code = res.at?.searchParams.get("code");
	if (!code) throw new Error(`the authorization endpoint gave no code: ${res.status}`);
	return { code, verifier, challenge };
}

async function madeAt(i: Instance, user: User): Promise<Made> {
	const place = { i };
	const browser = browserAt(() => place.i.baseUrl, issuer, user);
	const cookie = await browser.login();
	const code = await codeFor(browser);
	const redeemed = await redeemAt(i, await codeFor(browser));
	expect(said(redeemed)).toEqual([200, "Bearer"]);
	const granted = await sessionGrantAt(i, cookie);
	expect([granted.status, granted.body]).toMatchObject([200, { token_type: "Bearer" }]);
	return {
		user,
		place,
		browser,
		cookie,
		code,
		access: String(redeemed.body.access_token),
		refresh: String(redeemed.body.refresh_token),
		sessionToken: String(granted.body.access_token),
	};
}

/** Whether the session still lets its user in: a silent authorization answers a code or login_required. */
async function letsIn(m: Made) {
	const asked = await m.browser.authorize({
		response_type: "code",
		client_id: app.id,
		redirect_uri: callback,
		state: "s2",
		scope: "openid",
		prompt: "none",
		code_challenge: m.code.challenge,
		code_challenge_method: "S256",
	});
	return asked.at?.searchParams.get("code") ? "code" : asked.at?.searchParams.get("error");
}

/**
 * Everything the user's login made is refused at the instance: the session lets no one in, the code
 * gives nothing (used up before it is checked, as code-grant does, it has no token noted on it), the
 * refresh token is not rotated (its rotation never written), both access tokens are inactive, and no
 * session grant is given.
 */
async function refusedAt(i: Instance, m: Made) {
	m.place.i = i;
	expect(await letsIn(m)).toBe("login_required");
	expect(said(await redeemAt(i, m.code))).toEqual([400, "invalid_grant"]);
	expect(successes(i, codeNoted(m.code))).toEqual([]);
	expect(said(await refreshAt(i, m.refresh))).toEqual([400, "invalid_grant"]);
	expect(successes(i, rotationFrom(m.refresh))).toEqual([]);
	expect(await activeAt(i, m.access)).toBe(false);
	expect(await activeAt(i, m.sessionToken)).toBe(false);
	const granted = await sessionGrantAt(i, m.cookie);
	expect([granted.status, granted.body.error]).toEqual([401, "unauthorized"]);
}

/** Another user's login is untouched at the instance. */
async function passesAt(i: Instance, m: Made) {
	m.place.i = i;
	expect(await letsIn(m)).toBe("code");
	expect(await activeAt(i, m.access)).toBe(true);
}

/** No follower wrote, on any instance, since `from`: no session of the subject began closing. */
const unfollowed = (d: Deployed, from: number) => {
	for (const i of d.instances) {
		expect(successes(i, closingAdded).filter((e) => e.at > from)).toEqual([]);
	}
};

/** The control: with no fault, a revocation writes the boundary, its followers run, it answers complete, and what the login made is refused. */
async function control(d: Deployed) {
	const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
	const m = await madeAt(a, users.carol);
	const from = performance.now();
	expect(await revokeAt(a, users.carol.subject)).toMatchObject(complete);
	expect(successes(a, boundaryOf(users.carol.subject)).length).toBeGreaterThan(0);
	expect(successes(a, closingAdded).filter((e) => e.at > from).length).toBeGreaterThan(0);
	await refusedAt(b, m);
}

/** Healed: the instance is ready, the revocation sent again finishes, and a new login of another user passes. */
async function healed(i: Instance, subject: string) {
	await ready(i);
	expect(await revokeAt(i, subject)).toMatchObject(complete);
	await passesAt(i, await madeAt(i, users.bob));
}

describe("a subject's boundary refusing, from any instance, what was made before it, under faults", () => {
	it("refuses what was made before a boundary whose write's answer is lost once, the resend taking the first answer [guarantee-4-a] {fault:Lr}", async () => {
		await on({ name: "revocation-boundary-lr", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(d);
			const [m, other] = [await madeAt(a, users.alice), await madeAt(a, users.bob)];
			const from = performance.now();
			const following = a.relay.hold(closingAdded);
			const drop = a.relay.dropReplyTo(boundaryOf(users.alice.subject));
			const asked = revokeAt(a, users.alice.subject);
			const dropped = await drop.first;
			expect(dropped.collateral.filter((x) => isStoreOperation(x.command))).toEqual([]);
			// Resent under its mark, the write took the first answer; the boundary confirmed, the followers begin.
			const held = await following;
			const resent = successes(a, boundaryOf(users.alice.subject)).filter(
				(e) => e.at > from && sameMark(dropped.command, e.command),
			);
			expect(resent.length).toBeGreaterThan(1);
			unfollowed(d, from);
			await refusedAt(b, m);
			await passesAt(b, other);
			held.release();
			expect(await asked).toMatchObject(complete);
			await healed(a, users.alice.subject);
		});
	});

	it("never answers done for a boundary every answer to whose write is lost, and refuses what was made before it [guarantee-4-a] {fault:Lx}", async () => {
		await on({ name: "revocation-boundary-lx", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(d);
			const [m, other] = [await madeAt(a, users.alice), await madeAt(a, users.bob)];
			const from = performance.now();
			const drop = a.relay.dropReplyTo(boundaryOf(users.alice.subject), { resends: sameMark });
			const answer = await revokeAt(a, users.alice.subject);
			await drop.first;
			drop.end();
			expect(drop.resends.length).toBeGreaterThan(0);
			// Its write unconfirmed: not done, and no follower was called.
			expect(answered(answer)).toEqual(unknown);
			unfollowed(d, from);
			// The write took effect on Redis, unheard: the boundary refuses at another instance.
			await refusedAt(b, m);
			await passesAt(b, other);
			await healed(a, users.alice.subject);
		});
	});

	it("refuses, after a caught-up replica is promoted, what was made before a boundary written but whose followers did not finish [guarantee-4-a] {fault:F}", async () => {
		await on({ name: "revocation-boundary-f", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(d);
			const [m, other] = [await madeAt(a, users.alice), await madeAt(a, users.bob)];
			const from = performance.now();
			const following = a.relay.hold(closingAdded);
			const asked = revokeAt(a, users.alice.subject);
			// The followers begin only once the boundary's write is confirmed.
			await following;
			const [next, ...others] = d.topology.replicas();
			if (!next) throw new Error("a replica");
			// The old primary goes, the held write with its connection; A is left pointing at it, so its
			// followers cannot finish there, and B moves to the new primary.
			await d.topology.promote({ replica: next, reattach: others });
			b.relay.switchUpstream(d.topology.primary().upstream());
			b.relay.reset("all");
			await replicasOnline(d);
			await ready(b);
			unfollowed(d, from);
			await refusedAt(b, m);
			await passesAt(b, other);
			// Written, everything reading it refuses; a follower did not finish: never done.
			expect(answered(await asked)).toEqual(incomplete);
			a.relay.switchUpstream(d.topology.primary().upstream());
			a.relay.reset("all");
			await healed(a, users.alice.subject);
		});
	});

	it("refuses, after Redis is killed at once and started again, what was made before a boundary written but whose followers had not run [guarantee-4-a] {fault:C}", async ({
		annotate,
	}) => {
		await on({ name: "revocation-boundary-c", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(d);
			const [m, other] = [await madeAt(a, users.alice), await madeAt(a, users.bob)];
			const from = performance.now();
			const following = a.relay.hold(closingAdded);
			const asked = revokeAt(a, users.alice.subject);
			await following;
			// Nothing from A reaches Redis until B has read: its followers' resends wait with it.
			a.relay.stall("up");
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			b.relay.switchUpstream(d.topology.primary().upstream());
			b.relay.reset("all");
			await replicasOnline(d);
			await ready(b);
			unfollowed(d, from);
			await refusedAt(b, m);
			await passesAt(b, other);
			const restarted = performance.now();
			a.relay.switchUpstream(d.topology.primary().upstream());
			a.relay.reset("all");
			a.relay.resume();
			// Resent within their patience, the followers may finish on the server started again; done is
			// answered only so.
			const answer = await asked;
			if (answer.status === 200) {
				expect(answer).toMatchObject(complete);
				expect(successes(a, closingAdded).some((e) => e.at > restarted)).toBe(true);
				await annotate("answered complete, its followers finished on Redis started again");
			} else {
				expect(answered(answer)).toEqual(incomplete);
				await annotate("answered incomplete");
			}
			await healed(a, users.alice.subject);
		});
	});

	it("refuses, at another instance, what was made before a boundary whose instance was killed after writing it and before answering [guarantee-4-a] {fault:K}", async () => {
		await on({ name: "revocation-boundary-k", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(d);
			const [m, other] = [await madeAt(b, users.alice), await madeAt(b, users.bob)];
			const from = performance.now();
			// The boundary's confirmation held once its write has run, before the instance can answer.
			let held: Promise<unknown> | undefined;
			const written = a.relay.observe(boundaryOf(users.alice.subject)).then((e) => {
				held = a.relay.hold(confirmation({ replicas: 1 }));
				return e;
			});
			const answer = revokeAt(a, users.alice.subject).catch(() => undefined);
			await written;
			await held;
			const ended = await a.kill();
			expect(ended.signal).toBe("SIGKILL");
			// No answer from the instance: the trace in front of it answers 502 for one gone.
			expect([undefined, 502]).toContain((await answer)?.status);
			unfollowed(d, from);
			await refusedAt(b, m);
			await passesAt(b, other);
			await healed(b, users.alice.subject);
		});
	});

	it("refuses, at another instance, what was made before a boundary while its revocation's followers are still to run [guarantee-4-a] {fault:H2}", async () => {
		await on({ name: "revocation-boundary-h2", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(d);
			const [m, other] = [await madeAt(a, users.alice), await madeAt(a, users.bob)];
			const from = performance.now();
			const following = a.relay.hold(closingAdded);
			const asked = revokeAt(a, users.alice.subject);
			const held = await following;
			unfollowed(d, from);
			await refusedAt(b, m);
			await passesAt(b, other);
			held.release();
			expect(await asked).toMatchObject(complete);
			await healed(a, users.alice.subject);
		});
	});

	it("creates one boundary for a subject two instances revoke at once, both answering done, and refuses what was made before it at a third [guarantee-4-a] {fault:H2}", async () => {
		await on({ name: "revocation-boundary-h2-together", scene, instances: 3 }, async (d) => {
			const [a, b, c] = [instanceOf(d, 0), instanceOf(d, 1), instanceOf(d, 2)];
			await control(d);
			const [m, other] = [await madeAt(c, users.alice), await madeAt(c, users.bob)];
			const from = performance.now();
			// Both have found no boundary and are about to create one; each then holds its followers.
			const creating = [
				a.relay.hold(boundaryCreated(users.alice.subject)),
				b.relay.hold(boundaryCreated(users.alice.subject)),
			];
			const following = [a.relay.hold(closingAdded), b.relay.hold(closingAdded)];
			const asked = [revokeAt(a, users.alice.subject), revokeAt(b, users.alice.subject)];
			for (const held of await Promise.all(creating)) held.release();
			const followers = await Promise.all(following);
			// One created it; the other found it held and wrote it from that. A write held past the
			// command timeout is resent under its mark and answered again, so creations are counted by mark.
			const created = [a, b].flatMap((i) =>
				successes(i, boundaryCreated(users.alice.subject)).filter((e) => e.at > from),
			);
			const marks = created.filter(
				(e, n) => created.findIndex((f) => sameMark(f.command, e.command)) === n,
			);
			expect(created.length).toBeGreaterThan(0);
			expect(marks).toHaveLength(1);
			unfollowed(d, from);
			await refusedAt(c, m);
			await passesAt(c, other);
			for (const held of followers) held.release();
			for (const answer of await Promise.all(asked)) expect(answer).toMatchObject(complete);
			await healed(c, users.alice.subject);
		});
	});
});
