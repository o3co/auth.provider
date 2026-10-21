import type { Cookies } from "@mod/cookies";
import type { HttpRequest } from "@mod/http";
import { type Clock, type Log, type Random, Unavailable } from "@mod/kernel";
import {
	type AuthContext,
	type ClosingParticipants,
	type Entry,
	type EntryJudge,
	type EntryLevel,
	type Session,
	type Sessions,
	sessionRules,
} from "@mod/session";
import type { SubjectRevocation } from "@mod/subject-revocation";
import { keptAtLogin, keptAttributes } from "../attributes.ts";
import type {
	ChangedSession,
	ClosingList,
	CookieIndex,
	SessionStore,
	StoredSession,
	SubjectSessions,
} from "../store.ts";
import { authenticatedAtOf, checkAuthenticatedAt } from "./authenticated.ts";
import { listingOver } from "./listing/listing.ts";
import { fromStored, type SessionRecord, toStored } from "./record.ts";

export { fromStored, type SessionRecord, toStored };

export type OpenRecord = Extract<SessionRecord, { state: "open" }>;
type ClosingRecord = Extract<SessionRecord, { state: "closing" }>;

export interface LifecycleParts {
	readonly kept: SessionStore;
	readonly index: CookieIndex;
	readonly closings: ClosingList;
	readonly listed: SubjectSessions;
	readonly revocation: SubjectRevocation;
	readonly closing: ClosingParticipants;
	readonly judge: EntryJudge;
	readonly jar: Cookies;
	readonly clock: Clock;
	readonly random: Random;
	readonly log: Log;
	readonly lifetimeMs: number;
	readonly sweepMs: number;
	/** Whether a time is within the recent-authentication window, the floor's for changing credentials. */
	readonly recent: (at: number) => boolean;
}

export interface Lifecycle {
	/** The handle a well-formed session cookie opens, if any. */
	handleIn(request: HttpRequest): Promise<string | undefined>;
	secretIn(request: HttpRequest): string | undefined;
	/** The record, while it is open and after the subject's revocation boundary. */
	liveAt(handle: string): Promise<OpenRecord | undefined>;
	entryAt(handle: string, level: EntryLevel): Promise<Entry>;
	entryIn(request: HttpRequest, level: EntryLevel): Promise<Entry>;
	/** As `complete`: a new session over the request's earlier one. */
	open: Sessions["complete"];
	close: Sessions["close"];
	/** Closes the session the request's cookie opens, if any, and destroys the cookie it carries. */
	closeIn: Sessions["closeRequest"];
	sweep(stopping: AbortSignal): Promise<void>;
	/** A new secret indexed to the handle, as a cookie for `lifetimeMs`. */
	issueSecret(handle: string, lifetimeMs: number): Promise<{ readonly cookie: string }>;
	retireSecret(secret: string): Promise<void>;
	/** The session a record shows, frozen. */
	sessionOf(handle: string, record: AuthContext): Session;
}

const maxRetryMs = 3_600_000;
const secretShape = /^[A-Za-z0-9_-]{43}$/;

export function lifecycleOver(parts: LifecycleParts): Lifecycle {
	const { kept, index, closings, listed, revocation, jar, clock, log } = parts;
	const { lifetimeMs, sweepMs } = parts;
	const shortOf = sessionRules.judgedShortOf(parts.judge, parts.recent);
	/** When this host may next sweep a closing whose record it cannot read, and since when it failed. */
	const unread = new Map<string, { readonly since: number; readonly retryAt: number }>();
	/** When to retry a closing that failed: after half its age, from the sweep interval up to an hour. Logged. */
	const retryOf = (handle: string, since: number | undefined) => {
		const at = clock.now();
		const from = since ?? at;
		log.warn("session-lifecycle.closing_pending", {
			handle,
			ageSeconds: Math.round((at - from) / 1000),
		});
		return { since: from, retryAt: at + Math.min(maxRetryMs, Math.max(sweepMs, (at - from) / 2)) };
	};
	/** Puts off a closing whose record this cannot read: the record is left as it is, so only this host knows. */
	const putOffUnread = (handle: string) => {
		unread.set(handle, retryOf(handle, unread.get(handle)?.since));
	};
	/** Puts off a closing whose participants failed, in its record. */
	const putOff = async (handle: string, record: ClosingRecord) => {
		const { retryAt } = retryOf(handle, record.closingSince);
		await kept.update(handle, (stored) => {
			// Only a closing waits for a retry: one closed meanwhile, or its mark, is left as it is.
			const was = fromStored(stored);
			return was?.state === "closing" ? { value: toStored({ ...was, retryAt }) } : undefined;
		});
	};
	const listing = listingOver({
		listed,
		closings,
		log,
		leftOf: (handle) => leftOf(handle),
		endOpen: (handle) => endOpen(handle),
		close: (handle) => close(handle),
	});
	const random = () => Buffer.from(parts.random.bytes(32)).toString("base64url");
	const secretIn = (request: HttpRequest) => {
		const carried = jar.lookup(request, "session");
		return carried.kind === "found" && secretShape.test(carried.value) ? carried.value : undefined;
	};
	/** Which session a cookie's secret opens. */
	const handleIn = async (request: HttpRequest) => {
		const secret = secretIn(request);
		return secret ? index.read(secret) : undefined;
	};
	const contextOf = (record: AuthContext): AuthContext => {
		const attributes = keptAttributes(record.attributes);
		return Object.freeze({
			subject: record.subject,
			amr: Object.freeze([...record.amr]),
			authenticatedAt: record.authenticatedAt,
			...(record.authenticatedAtUnknown ? { authenticatedAtUnknown: true } : {}),
			...(record.raisedAt === undefined ? {} : { raisedAt: record.raisedAt }),
			...(record.raisedAmr === undefined
				? {}
				: { raisedAmr: Object.freeze([...record.raisedAmr]) }),
			...(attributes === undefined ? {} : { attributes }),
		});
	};
	const sessionOf = (handle: string, record: AuthContext): Session =>
		Object.freeze({ id: handle, context: contextOf(record) });
	const endedAt = (record: OpenRecord, at: number) => record.openedAt + lifetimeMs <= at;
	/** Closed, and kept for the lifetime from now. */
	const closedOf = (was: SessionRecord): ChangedSession => ({
		value: toStored({ ...was, state: "closed" }),
		lifetimeMs,
	});
	/** Goes on only when the place answered created; anything else is unavailable. */
	const created = async (saving: Promise<"created" | "exists">) => {
		if ((await saving) !== "created") throw new Unavailable("session");
	};
	/**
	 * Moves forward to `target`, never back, always writing to confirm it; a missing record is marked
	 * closed. Answers the record after, and the state it was found in (none when there was no record).
	 */
	const advance = async (
		handle: string,
		target: "closing" | "closed",
	): Promise<{ readonly record: SessionRecord; readonly from?: SessionRecord["state"] }> => {
		const at = clock.now();
		const step = (stored: StoredSession): ChangedSession | undefined => {
			const was = fromStored(stored);
			if (!was) return undefined;
			if (was.state === "closed" || target === "closed") return closedOf(was);
			// A closing is kept until it is closed, so its participants are never skipped, even for a
			// session the lifetime in force has ended: its tokens still live.
			const closing = { ...was, state: "closing" as const, closingSince: was.closingSince ?? at };
			return { value: toStored(closing), lifetimeMs: "endless" };
		};
		const written = await kept.update(handle, step);
		if (written) {
			// A record this cannot read is left as it is, and its close cannot go on.
			const after = fromStored(written.after);
			const before = fromStored(written.before);
			if (!after || !before) {
				putOffUnread(handle);
				throw new Unavailable("session");
			}
			return { record: after, from: before.state };
		}
		const mark: SessionRecord = { format: 2, state: "closed" };
		// A record placed meanwhile is moved on when the close is asked again.
		await created(kept.save(handle, toStored(mark), lifetimeMs));
		return { record: mark };
	};
	const close: Sessions["close"] = async (handle, request) => {
		const cookies =
			request && (await handleIn(request)) === handle ? [jar.write("session", "", 0)] : [];
		// Added to the closings first, so a closing that stops halfway is found and finished.
		await closings.add(handle);
		const { record, from } = await advance(handle, "closing");
		const moved = {
			...("subject" in record ? { session: { id: handle, subject: record.subject } } : {}),
			...(from === undefined ? {} : { from }),
		};
		if (record.state === "closing") {
			const failed = await parts.closing.closing(sessionOf(handle, record));
			for (const failure of failed) log.warn("session-lifecycle.participant_failed", failure);
			if (failed.length > 0) {
				await putOff(handle, record);
				return { kind: "pending", cookies, ...moved };
			}
			await advance(handle, "closed");
		}
		if ("subject" in record) await listing.unlist(record.subject, handle);
		await closings.done(handle);
		return { kind: "closed", cookies, ...moved };
	};
	/** What a session has left of the lifetime in force from its opening: none once closed, all of it when its record cannot be read. */
	const leftOf = async (handle: string) => {
		const stored = await kept.read(handle);
		const record = fromStored(stored);
		if (!record) return stored === undefined ? 0 : lifetimeMs;
		if (record.state === "closed") return 0;
		return record.openedAt + lifetimeMs - clock.now();
	};
	/** Ends an open record there, calling no participants. */
	const endOpen = (handle: string) =>
		kept.update(handle, (stored) => {
			const was = fromStored(stored);
			return was?.state === "open" ? closedOf(was) : undefined;
		});
	const closeIn: Sessions["closeRequest"] = async (request) => {
		const handle = await handleIn(request);
		const closed = handle ? await close(handle) : { kind: "closed" as const };
		// A cookie that opens nothing any more is destroyed all the same, as is one withheld.
		const carried = jar.lookup(request, "session").kind !== "absent";
		return { ...closed, cookies: carried ? [jar.write("session", "", 0)] : [] };
	};
	/** When a kept closing is next due: its record's retry time, or this host's for one it cannot read. */
	const dueOf = (handle: string, record: SessionRecord | undefined) =>
		(record ? ("retryAt" in record ? record.retryAt : undefined) : unread.get(handle)?.retryAt) ??
		0;
	/** Goes on with every pending closing that is due; one that fails does not hold up the rest. */
	const sweep = async (stopping: AbortSignal) => {
		const seen = new Set<string>();
		const { failed } = await closings.each(async (handle) => {
			if (stopping.aborted) return;
			seen.add(handle);
			if (dueOf(handle, fromStored(await kept.read(handle))) <= clock.now()) await close(handle);
		});
		// Forgets the closings no longer kept, finished here or by another host.
		if (!stopping.aborted) {
			for (const handle of unread.keys()) if (!seen.has(handle)) unread.delete(handle);
		}
		if (failed > 0) log.warn("session-lifecycle.sweep_failed", { count: failed });
	};
	const liveAt = async (handle: string) => {
		const found = fromStored(await kept.read(handle));
		if (found?.state !== "open") return undefined;
		// The lifetime in force decides; a session it ended is closed now, so a longer one never brings it back.
		if (endedAt(found, clock.now())) {
			await endOpen(handle);
			return undefined;
		}
		const revoked = (await revocation.check(found.subject, found.openedAt)) === "revoked";
		return revoked ? undefined : found;
	};
	const entryAt = async (handle: string, level: EntryLevel): Promise<Entry> => {
		const found = await liveAt(handle);
		if (!found) return { kind: "absent" };
		const session = sessionOf(handle, found);
		const short = await shortOf(session.context, level);
		if (!(await liveAt(handle))) return { kind: "absent" };
		if (short) return { kind: "short", ...short };
		return { kind: "entered", session, endsAt: found.openedAt + lifetimeMs };
	};
	const entryIn = async (request: HttpRequest, level: EntryLevel): Promise<Entry> => {
		const secret = secretIn(request);
		const handle = secret ? await index.read(secret) : undefined;
		if (!secret || !handle) return { kind: "absent" };
		const entry = await entryAt(handle, level);
		if (entry.kind === "absent") return entry;
		return (await index.read(secret)) === handle ? entry : { kind: "absent" };
	};
	const issueSecret = async (handle: string, forMs: number) => {
		const secret = random();
		await created(index.save(secret, handle, forMs));
		return { cookie: jar.write("session", secret, Math.max(1, Math.floor(forMs / 1000))) };
	};
	const open: Sessions["complete"] = async (request, facts) => {
		checkAuthenticatedAt(facts);
		// The earlier session is closed first; the login fails if that close cannot even be added to the closings.
		const earlier = await handleIn(request);
		if (earlier) await close(earlier);
		// A new session every time, under a new handle: a login never carries on an earlier one.
		const handle = random();
		const openedAt = clock.now();
		const attributes = keptAtLogin(facts.attributes, log);
		const context = {
			subject: facts.subject,
			amr: [...facts.amr],
			...authenticatedAtOf(facts, openedAt, log),
			...(attributes === undefined ? {} : { attributes }),
		};
		const record: SessionRecord = { format: 2, state: "open", ...context, openedAt };
		await created(kept.save(handle, toStored(record), lifetimeMs));
		// Listed before its cookie is made, so a revocation finds every session anyone can enter.
		const { pushedOut } = await listed.add(facts.subject, handle, lifetimeMs);
		if (pushedOut.length > 0) await listing.closePushedOut(facts.subject, handle, pushedOut);
		const { cookie } = await issueSecret(handle, lifetimeMs);
		return { session: sessionOf(handle, context), cookies: [cookie] };
	};
	return {
		handleIn,
		secretIn,
		liveAt,
		entryAt,
		entryIn,
		open,
		close,
		closeIn,
		sweep,
		issueSecret,
		retireSecret: (secret) => index.remove(secret),
		sessionOf,
	};
}
