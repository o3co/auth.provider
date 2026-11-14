import { createHash } from "node:crypto";
import type { Log } from "@mod/kernel";
import { z } from "zod";
import type { NoticeBodies, NoticeQueue, PendingNotices } from "../store.ts";

/** What a notice tells: one client, a session's handle and subject, the time it is given up, its token's id. */
export interface Notice {
	readonly client: string;
	readonly session: string;
	readonly subject: string;
	/** Epoch ms on `kernel`'s clock. */
	readonly until: number;
	readonly jti?: string;
}

/**
 * A notice as 0.19 kept it, and as a body is read: fields it does not know are left unread, so one a
 * newer host wrote still reads; `after`, on a 0.19 notice alone, is the time before which it is not
 * tried again.
 */
const noticeShape = z.object({
	client: z.string(),
	session: z.string(),
	subject: z.string(),
	until: z.number(),
	jti: z.string().min(1).optional(),
	after: z.number().optional(),
});

const parsed = (text: string) => {
	try {
		const read = noticeShape.safeParse(JSON.parse(text));
		return read.success ? read.data : undefined;
	} catch {
		return undefined;
	}
};

/** A 0.19 notice's fields and its `after`, or none where it does not read as one. */
export const pendingOf = (notice: string) => parsed(notice);

/**
 * A notice's body in its one fixed form: format 1, its fields in this order, UTF-8 JSON, no `after`.
 * Kept as this exact string, so the id hashed from it is the body's own.
 */
export const bodyOf = (n: Notice): string =>
	JSON.stringify({
		format: 1,
		client: n.client,
		session: n.session,
		subject: n.subject,
		until: n.until,
		...(n.jti === undefined ? {} : { jti: n.jti }),
	});

/** A body's id: the SHA-256 of its string, so the same notice always has the same id. */
export const idOf = (body: string) => createHash("sha256").update(body, "utf8").digest("base64url");

/** A body read back under `id`: its notice where it hashes to that id and reads as one; none otherwise. */
export const bodyRead = (id: string, body: string): Notice | undefined => {
	if (idOf(body) !== id) return undefined;
	const n = parsed(body);
	return (
		n && {
			client: n.client,
			session: n.session,
			subject: n.subject,
			until: n.until,
			...(n.jti ? { jti: n.jti } : {}),
		}
	);
};

/** An entry: a body's id, and the time before which its notice is not tried again. */
export const entryOf = (id: string, after?: number) =>
	JSON.stringify(after === undefined ? { id } : { id, after });

const entryShape = z.object({ id: z.string().min(1), after: z.number().optional() });
/** An entry's id and time, or none where it does not read as one. */
export const entryRead = (entry: string) => {
	try {
		const read = entryShape.safeParse(JSON.parse(entry));
		return read.success ? read.data : undefined;
	} catch {
		return undefined;
	}
};

/**
 * Keeps a notice's body under its subject until it is given up, then adds its entry: only after the
 * create answered `created` or `exists`, so an entry never names a body not kept. `erased` where the
 * subject is erased: nothing is kept.
 */
export async function keep(
	stores: { readonly bodies: NoticeBodies; readonly queue: NoticeQueue },
	notice: Notice,
	now: number,
	after?: number,
): Promise<"kept" | "erased"> {
	const body = bodyOf(notice);
	const id = idOf(body);
	const made = await stores.bodies.create(
		id,
		body,
		Math.max(1, notice.until - now),
		notice.subject,
	);
	if (made === "erased") return "erased";
	await stores.queue.add(entryOf(id, after));
	return "kept";
}

/**
 * A 0.19 notice past its time, or one that does not read as a notice: done, and logged, as the
 * worker drops one.
 */
export async function dropped(pending: PendingNotices, notice: string, log: Log, now: number) {
	const fields = pendingOf(notice);
	if (fields && now <= fields.until) return false;
	if (fields) log.warn("rp-logout.notice_expired", { client: fields.client });
	else log.warn("rp-logout.notice_unreadable", {});
	await pending.done(notice);
	return true;
}

/**
 * Moves a 0.19 notice to a body and an entry, then done: its `after` on the entry. One past its
 * time or unreadable is dropped; one whose subject is erased is done, nothing kept, logged naming no
 * subject.
 */
export async function move(
	stores: {
		readonly bodies: NoticeBodies;
		readonly queue: NoticeQueue;
		readonly pending: PendingNotices;
	},
	notice: string,
	log: Log,
	now: number,
): Promise<"moved" | "dropped" | "withheld"> {
	if (await dropped(stores.pending, notice, log, now)) return "dropped";
	const fields = pendingOf(notice);
	if (!fields) return "dropped";
	const { after, jti, ...rest } = fields;
	const kept = await keep(stores, { ...rest, ...(jti ? { jti } : {}) }, now, after);
	if (kept === "erased") log.warn("rp-logout.notice_withheld", { client: fields.client });
	await stores.pending.done(notice);
	return kept === "erased" ? "withheld" : "moved";
}
