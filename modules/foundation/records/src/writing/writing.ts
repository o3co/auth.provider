import { createHash } from "node:crypto";
import { BuildRefused, isUnavailable, type Log, type Random, Unavailable } from "@mod/kernel";
import type { Expiry, Json, Key, Space, Store, WriteOptions } from "@mod/store";

export interface Place {
	readonly store: Store;
	readonly space: Space;
	/** Where a refusal the caller cannot tell apart is told, with the space it came from. */
	readonly log?: Log;
	/** Where the unguessable marks that settle a resent write come from: the kernel's randomness. */
	readonly random: Random;
}

/** What a write hands the caller deciding it: the store-clock time past which that attempt is refused. */
export interface Attempt {
	readonly deadline: number;
}

/** A changed value, and its new lifetime from the write, or none to end it; without one, the lifetime stays. */
export interface Changed<T> {
	readonly value: T;
	readonly lifetimeMs?: number | "endless";
}

/** A write is no longer resent once the pauses between its sends add up to this. */
export const patienceMs = 10_000;
/** How many times a write is tried again after losing a race, before it answers unavailable. */
export const attempts = 8;
/** The first pause before a resend, doubled after each, up to the longest. */
const firstPauseMs = 50;
const longestPauseMs = 1000;
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Sends one write until the store answers. Each resend is the same request under the same mark,
 * so a write whose answer was lost gets the answer it first had and never takes effect twice.
 * Patience is counted in pauses, so no clock is read.
 */
export async function untilAnswered<A>(send: () => Promise<A>): Promise<A> {
	let waited = 0;
	let wait = firstPauseMs;
	for (;;) {
		try {
			return await send();
		} catch (error) {
			if (!isUnavailable(error) || waited + wait > patienceMs) throw error;
		}
		await pause(wait);
		waited += wait;
		wait = Math.min(wait * 2, longestPauseMs);
	}
}

/** What an attempt answers where it lost a race, or found nothing it could confirm: try again. */
export const again = Symbol("again");

/** Runs `attempt` until it answers anything but `again`, at most `attempts` times; past them, unavailable. */
export async function retried<A>(attempt: () => Promise<A | typeof again>): Promise<A> {
	for (let tried = 0; tried < attempts; tried++) {
		const answered = await attempt();
		if (answered !== again) return answered;
	}
	throw new Unavailable("records");
}

// A mark is random, not a hash of the write: two writers putting the same value on the same
// version would share a hashed mark, and the store would answer both as the one that wrote.
const markFrom = (place: Place) => Buffer.from(place.random.bytes(16)).toString("base64url");
/** Writes that land after this store-clock time are refused, so a lost send cannot act later. */
export const writeDeadline = (now: number) => now + patienceMs;
export const markedAt = (place: Place, now: number) => ({
	idempotency: markFrom(place),
	deadline: writeDeadline(now),
});

/** Writes a mark of its own only while the key holds what was read, at that version or none. */
export async function confirmedAsRead(
	place: Place,
	key: Key,
	version: string | undefined,
	deadline: number,
) {
	const markKey = { space: key.space, partition: key.partition, name: "settled" };
	const marked = { idempotency: markFrom(place), deadline };
	const confirmed = await untilAnswered(() =>
		place.store.batch(
			[version === undefined ? { key, absent: true } : { key, version }],
			[{ key: markKey, put: true, expiry: { kind: "after", ms: 1 } }],
			marked,
		),
	);
	return confirmed.kind === "committed";
}

/**
 * Reads the key, decides on what it holds, and writes on exactly what was read, under a mark;
 * losing a race decides again on what is there now. Answers what the key held and holds now.
 */
export async function rewrite(
	place: Place,
	key: Key,
	decide: (
		current: Json | undefined,
		attempt: Attempt,
	) => { readonly value: Json; readonly expiry: Expiry } | undefined,
): Promise<{ readonly before: Json | undefined; readonly after: Json | undefined }> {
	return retried(async () => {
		const { entry, now } = await place.store.get(key);
		const before = entry?.value;
		// Decided knowing the deadline this attempt is written with, a retry deciding again with its own.
		const marked = markedAt(place, now);
		const decided = decide(before, { deadline: marked.deadline });
		if (!decided) {
			if (await confirmedAsRead(place, key, entry?.version, marked.deadline)) {
				return { before, after: before };
			}
			return again;
		}
		const options: WriteOptions = { expiry: decided.expiry, ...marked };
		const written = entry
			? await untilAnswered(() => place.store.replaceIf(key, entry.version, decided.value, options))
			: await untilAnswered(() => place.store.putIfAbsent(key, decided.value, options));
		if (written.kind === "written") return { before, after: decided.value };
		if (written.kind === "late" || written.kind === "reused") throw new Unavailable("records");
		return again;
	});
}

export function expiryOf(lifetimeMs: number | "endless" | undefined): Expiry {
	if (lifetimeMs === undefined) return { kind: "keep" };
	if (lifetimeMs === "endless") return { kind: "never" };
	return { kind: "after", ms: Math.max(1, lifetimeMs) };
}

/** The kind each space was opened for, by store: a space's scan lists every record's key, so it holds one kind. */
const openedFor = new WeakMap<Store, Map<string, "records" | "secret records">>();
/** The name a record under a secret is kept by: `1.` and the base64url SHA-256 of its space's name, a line feed and the secret. */
export const nameOf = (space: Space, secret: string) =>
	`1.${createHash("sha256").update(`${space.name}\n${secret}`).digest("base64url")}`;

/** The categories of a space holding a subject's data, which subject-records alone writes. */
const heldForSubjects = new Set(["online-indexed", "online-keyed", "bounded"]);

/**
 * Refuses the boot where a plain builder (records, under a secret, deferred work, keyed sets)
 * opens a space holding a subject's data: subject-records writes those, through `changeRecords`.
 */
export function plainDoor(place: Place) {
	const held = place.space.subjectData;
	if (held !== undefined && heldForSubjects.has(held)) {
		throw new BuildRefused(
			place.space.name,
			"a space holding a subject's data is written through subject-records",
		);
	}
}

export function claim(place: Place, kind: "records" | "secret records") {
	const kinds = openedFor.get(place.store) ?? new Map<string, "records" | "secret records">();
	openedFor.set(place.store, kinds);
	const held = kinds.get(place.space.name);
	if (held !== undefined && held !== kind) {
		// A refusal of the boot, named by the space, so the operator reads why.
		throw new BuildRefused(place.space.name, "a space holds records or secret records, not both");
	}
	kinds.set(place.space.name, kind);
}
