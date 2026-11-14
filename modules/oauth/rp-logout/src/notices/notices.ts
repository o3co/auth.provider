import { type Client, clients } from "@mod/clients";
import { issuer } from "@mod/issuer";
import { type BuildContext, type Clock, type Log, type Random, Unavailable } from "@mod/kernel";
import { type Keys, keys } from "@mod/keys";
import { DestinationRefused, type Outbound, outbound } from "@mod/outbound";
import type { Session } from "@mod/session";
import {
	bodyRead,
	entryOf,
	entryRead,
	keep,
	move,
	type Notice,
	pendingOf,
} from "../notice-body/notice-body.ts";
import { registration } from "../registration/registration.ts";
import type { Settings } from "../section.ts";
import {
	type NoticeBodies,
	type NoticeQueue,
	noticeBodies,
	noticeQueue,
	type PendingNotices,
	pendingNotices,
	type SessionClients,
	sessionClients,
} from "../store.ts";

/** A 0.19 notice's fields and its wait, or a body's notice. */
interface Fields {
	readonly client: string;
	readonly session: string;
	readonly subject: string;
	readonly until: number;
	readonly jti?: string | undefined;
	readonly after?: number | undefined;
}

/** Notices kept nowhere, their subject erased, whose one try would have been tried again: the close fails. */
export class NoticeUnsent extends Error {
	override readonly name = "NoticeUnsent";
	readonly clients: readonly string[];
	constructor(clients: readonly string[]) {
		super(`rp-logout: a notice kept nowhere is not delivered to ${clients.join(", ")}`);
		this.clients = clients;
	}
}

export interface NoticeParts {
	readonly keys: Pick<Keys, "sign">;
	readonly outbound: Outbound;
	readonly clients: { find(id: string): Promise<Client | undefined> };
	readonly issuer: string;
	readonly pending: PendingNotices;
	readonly bodies: NoticeBodies;
	readonly queue: NoticeQueue;
	readonly sessionClients: Pick<SessionClients, "members">;
	readonly clock: Clock;
	readonly random: Random;
	readonly log: Log;
	readonly notifyMs: number;
	/** Seconds a logout token lives; it is sent at once. */
	readonly tokenSeconds: number;
	/** How long a notice whose try failed waits before it is tried again. */
	readonly retryMs: number;
}

/** OpenID Connect Back-Channel Logout 1.0 §2.4: the event a logout token carries. */
const logoutEvent = "http://schemas.openid.net/event/backchannel-logout";
/** The client took the notice: Back-Channel Logout 1.0 §2.8 answers a logout done with `200`. */
const delivered = (status: number) => status >= 200 && status < 300;
/** A client that is busy or down may take it later; any other answer, §2.8's `400` among them, is final. */
const mayRetry = (status: number) => status === 408 || status === 429 || status >= 500;

export function noticesOver(p: NoticeParts) {
	const tokenId = () => Buffer.from(p.random.bytes(16)).toString("base64url");
	/** The logout token for a notice, issued now. */
	const logoutToken = (fields: Fields, withSession: boolean) => {
		const iat = Math.floor(p.clock.now() / 1000);
		return p.keys.sign(
			{
				iss: p.issuer,
				sub: fields.subject,
				aud: fields.client,
				iat,
				exp: iat + p.tokenSeconds,
				jti: fields.jti ?? tokenId(),
				events: { [logoutEvent]: {} },
				...(withSession ? { sid: fields.session } : {}),
			},
			"logout+jwt",
		);
	};
	/** The client's answer to the token posted as a form, or the refusal of `outbound`'s policy. */
	const posted = async (uri: string, token: string): Promise<number | DestinationRefused> => {
		const body = new URLSearchParams({ logout_token: token }).toString();
		const headers = { "content-type": "application/x-www-form-urlencoded" };
		try {
			return (await p.outbound.fetch(uri, { method: "POST", headers, body })).status;
		} catch (error) {
			if (DestinationRefused.is(error)) return error;
			throw error;
		}
	};
	/** One try at telling the client; a notice settled either way is done, and one to try again throws. */
	const attempt = async (fields: Fields, done: () => Promise<void>): Promise<void> => {
		const { client } = fields;
		const registered = (await p.clients.find(client))?.section(registration);
		const uri = registered?.["backchannel-logout-uri"];
		if (!registered || uri === undefined) return done();
		const token = await logoutToken(fields, registered["backchannel-logout-session-required"]);
		const answer = await posted(uri, token);
		if (DestinationRefused.is(answer)) {
			p.log.warn("rp-logout.backchannel_refused", { client, reason: answer.reason });
			return done();
		}
		if (delivered(answer)) return done();
		if (mayRetry(answer)) throw new Unavailable("rp-logout");
		p.log.warn("rp-logout.backchannel_rejected", { client, status: String(answer) });
		return done();
	};
	/**
	 * The time before which a notice whose try failed is not tried again: `retryMs` after it was last
	 * due, or after it was made where it never waited (Back-Channel Logout 1.0 §2.5), read from the
	 * notice alone, so every host failing it at once keeps the same one.
	 */
	const nextAfter = (fields: Fields) => (fields.after ?? fields.until - p.notifyMs) + p.retryMs;
	/** A 0.19 notice: tried once its wait is over; a failed try moves it to a body and an entry. */
	const send = async (notice: string): Promise<void> => {
		const fields = pendingOf(notice);
		const done = () => p.pending.done(notice);
		if (!fields) {
			p.log.warn("rp-logout.notice_unreadable", {});
			return done();
		}
		if (p.clock.now() > fields.until) {
			p.log.warn("rp-logout.notice_expired", { client: fields.client });
			return done();
		}
		if (fields.after !== undefined && p.clock.now() < fields.after) return;
		try {
			await attempt(fields, done);
		} catch (error) {
			// Moved to a body and an entry; where the store cannot, it stays as it was, for the next sweep.
			const moved = await move(p, notice, p.log, p.clock.now(), nextAfter(fields)).catch(
				() => undefined,
			);
			// Its subject erased, it is done: no notice is kept to count.
			if (moved === "withheld") return;
			throw error;
		}
	};
	/** Tries an entry's notice from its body, as `notices`' card says; an id in `tried` once a sweep. */
	const sendEntry = async (entry: string, tried?: Set<string>): Promise<void> => {
		const named = entryRead(entry);
		const done = () => p.queue.done(entry);
		if (!named) {
			p.log.warn("rp-logout.notice_unreadable", {});
			return done();
		}
		const body = await p.bodies.read(named.id);
		if (body === undefined) return done();
		if (tried?.has(named.id)) return;
		const fields = bodyRead(named.id, body);
		// A format this host does not know: left alone, to end at its own lifetime or a newer host.
		if (fields === "newer") throw new Error("rp-logout: a notice body of a newer format");
		const settle = async () => {
			await p.bodies.remove(named.id);
			await done();
		};
		if (!fields) {
			p.log.warn("rp-logout.notice_unreadable", {});
			return settle();
		}
		if (p.clock.now() > fields.until) {
			p.log.warn("rp-logout.notice_expired", { client: fields.client });
			return settle();
		}
		if (named.after !== undefined && p.clock.now() < named.after) return;
		tried?.add(named.id);
		try {
			await attempt(fields, settle);
		} catch (error) {
			// Its entry replaced, kept before the old one goes; the body is never changed.
			await p.queue
				.add(
					entryOf(
						named.id,
						nextAfter({ ...fields, ...(named.after ? { after: named.after } : {}) }),
					),
				)
				.then(done)
				.catch(() => undefined);
			throw error;
		}
	};
	return {
		/**
		 * Keeps a body and an entry for each client the session holds; answers the entries once all are
		 * kept, and the notices kept nowhere, their subject erased.
		 */
		closing: async (session: Session) => {
			const held = await p.sessionClients.members(session.id);
			const until = p.clock.now() + p.notifyMs;
			const { subject } = session.context;
			const entries: string[] = [];
			const withheld: Notice[] = [];
			for (const { member } of held) {
				const notice: Notice = {
					client: member,
					session: session.id,
					subject,
					until,
					jti: tokenId(),
				};
				const kept = await keep(p, notice, p.clock.now());
				if (kept === "erased") withheld.push(notice);
				else entries.push(kept.entry);
			}
			return { entries, withheld };
		},
		/** Tries each entry once and never rejects: one that fails stays for the sweep. */
		deliver: async (entries: readonly string[]): Promise<void> => {
			for (const entry of entries) await sendEntry(entry).catch(() => undefined);
		},
		/**
		 * Tries each notice kept nowhere once, logged naming no subject; throws `NoticeUnsent` where a
		 * try would be tried again.
		 */
		tellOnce: async (notices: readonly Notice[]): Promise<void> => {
			const unsent: string[] = [];
			for (const notice of notices) {
				const told = await attempt(notice, async () => {}).then(
					() => true,
					() => false,
				);
				p.log.warn("rp-logout.notice_unkept", { client: notice.client, told: String(told) });
				if (!told) unsent.push(notice.client);
			}
			if (unsent.length > 0) throw new NoticeUnsent(unsent);
		},
		/** Tries every entry, and every 0.19 notice, whose wait is over once; answers how many failed. */
		sweep: async () => {
			// Each body tried once a sweep: a replaced entry met again in a later shard is passed.
			const tried = new Set<string>();
			const entries = await p.queue.each((entry) => sendEntry(entry, tried));
			const pending = await p.pending.each(send);
			return { failed: entries.failed + pending.failed };
		},
	};
}

export type Notices = ReturnType<typeof noticesOver>;

/** What `noticesFrom` takes from the composition. */
export const noticesTakes = [
	keys,
	outbound,
	clients,
	issuer,
	pendingNotices,
	noticeBodies,
	noticeQueue,
	sessionClients,
] as const;

/** The notices, from the composition's contracts. */
export async function noticesFrom(c: BuildContext<Settings>): Promise<Notices> {
	return noticesOver({
		keys: await c.get(keys),
		outbound: await c.get(outbound),
		clients: await c.get(clients),
		issuer: (await c.get(issuer)).url,
		pending: await c.get(pendingNotices),
		bodies: await c.get(noticeBodies),
		queue: await c.get(noticeQueue),
		sessionClients: await c.get(sessionClients),
		clock: c.clock,
		random: c.random,
		log: c.log,
		notifyMs: c.section["notify-within"] * 1000,
		tokenSeconds: c.section["logout-token-lifetime"],
		// At least a sweep apart, so the sweep after a failure never tries it again at once.
		retryMs: c.section["sweep-interval"] * 1000,
	});
}
