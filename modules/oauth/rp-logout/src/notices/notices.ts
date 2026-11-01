import { type Client, clients } from "@mod/clients";
import { issuer } from "@mod/issuer";
import { type BuildContext, type Clock, type Log, type Random, Unavailable } from "@mod/kernel";
import { type Keys, keys } from "@mod/keys";
import { DestinationRefused, type Outbound, outbound } from "@mod/outbound";
import type { Session } from "@mod/session";
import { z } from "zod";
import { registration } from "../registration/registration.ts";
import type { Settings } from "../section.ts";
import {
	type PendingNotices,
	pendingNotices,
	type SessionClients,
	sessionClients,
} from "../store.ts";

/**
 * What a notice holds: one client to tell that a session closed, until a time (epoch ms on `kernel`'s
 * clock), the logout token's id every try sends, and, once a try failed, the time before which it is
 * not tried again. Fields it does not know are left unread, so a notice a newer host wrote is still
 * delivered; one with no id gets a new one on each try, and one with no such time is tried at once.
 */
const fieldsShape = z.object({
	client: z.string(),
	session: z.string(),
	subject: z.string(),
	until: z.number(),
	jti: z.string().min(1).optional(),
	after: z.number().optional(),
});
type Fields = z.infer<typeof fieldsShape>;

export interface NoticeParts {
	readonly keys: Pick<Keys, "sign">;
	readonly outbound: Outbound;
	readonly clients: { find(id: string): Promise<Client | undefined> };
	readonly issuer: string;
	readonly pending: PendingNotices;
	readonly sessionClients: Pick<SessionClients, "members">;
	readonly clock: Clock;
	readonly random: Random;
	readonly log: Log;
	readonly notifyMs: number;
	/** How long a notice whose try failed waits before it is tried again. */
	readonly retryMs: number;
}

/** OpenID Connect Back-Channel Logout 1.0 §2.4: the event a logout token carries. */
const logoutEvent = "http://schemas.openid.net/event/backchannel-logout";
/** Seconds a logout token lives; it is sent at once. */
const tokenSeconds = 300;
/** The client took the notice: Back-Channel Logout 1.0 §2.8 answers a logout done with `200`. */
const delivered = (status: number) => status >= 200 && status < 300;
/** A client that is busy or down may take it later; any other answer, §2.8's `400` among them, is final. */
const mayRetry = (status: number) => status === 408 || status === 429 || status >= 500;

/** A notice's fields, or none when it does not read as one. */
const fieldsOf = (notice: string): Fields | undefined => {
	try {
		const read = fieldsShape.safeParse(JSON.parse(notice));
		return read.success ? read.data : undefined;
	} catch {
		return undefined;
	}
};

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
				exp: iat + tokenSeconds,
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
	 * Keeps the notice to be tried no sooner than `retryMs` after it was last due, or after it was made
	 * where it never waited (Back-Channel Logout 1.0 §2.5), its other fields as they were, those it does
	 * not know among them. The time is read from the notice alone, never the clock, so every host that
	 * fails the same notice at once keeps the same one, which the store holds once. Kept before the old
	 * one goes, so a failure between leaves the notice twice, never none: the client tells the repeat
	 * by its id. Answers the notice kept.
	 */
	const later = async (notice: string, fields: Fields): Promise<string> => {
		const due = fields.after ?? fields.until - p.notifyMs;
		const next = JSON.stringify({ ...JSON.parse(notice), after: due + p.retryMs });
		await p.pending.add(next);
		await p.pending.done(notice);
		return next;
	};
	/**
	 * Tries a notice whose wait is over; one to try again is kept to wait, and throws. The notice kept
	 * goes into `kept`, so a sweep that comes upon it again, its time still past, passes over it.
	 */
	const send = async (notice: string, kept?: Set<string>): Promise<void> => {
		const fields = fieldsOf(notice);
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
			// Where the store cannot keep the wait either, the notice stays as it was, tried at the next sweep.
			const next = await later(notice, fields).catch(() => undefined);
			if (next !== undefined) kept?.add(next);
			throw error;
		}
	};
	return {
		/** Keeps a notice for each client the session holds; answers the notices once all are kept. */
		closing: async (session: Session): Promise<readonly string[]> => {
			const held = await p.sessionClients.members(session.id);
			const until = p.clock.now() + p.notifyMs;
			const { subject } = session.context;
			const notices = held.map(({ member }) =>
				JSON.stringify({ client: member, session: session.id, subject, until, jti: tokenId() }),
			);
			for (const notice of notices) await p.pending.add(notice);
			return notices;
		},
		/** Tries each notice once and never rejects: one that fails stays for the sweep. */
		deliver: async (notices: readonly string[]): Promise<void> => {
			for (const notice of notices) await send(notice).catch(() => undefined);
		},
		/** Tries every kept notice whose wait is over once, and one kept again in this sweep not again. */
		sweep: () => {
			const kept = new Set<string>();
			return p.pending.each((notice) =>
				kept.has(notice) ? Promise.resolve() : send(notice, kept),
			);
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
		sessionClients: await c.get(sessionClients),
		clock: c.clock,
		random: c.random,
		log: c.log,
		notifyMs: c.section["notify-within"] * 1000,
		// At least a sweep apart, so the sweep after a failure never tries it again at once.
		retryMs: c.section["sweep-interval"] * 1000,
	});
}
