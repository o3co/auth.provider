import { createHash } from "node:crypto";
import {
	type Command,
	type Match,
	storeRead,
	storeWrite,
	writtenValues,
} from "@mod/conformance/testing";

// What the area's fault scenes name of the store's inside, in one place: the Redis adapter's wire, the
// spaces and partitions the identity area's modules write. The scenes name only what this file offers.

/** The deployment's `redis.prefix`: the adapter's own, as no scene sets one. */
export const prefix = "store";

/** A store operation: the adapter runs each as a script; not the handshake each new connection makes, nor the confirming connection's rounds (`ROLE`, `INFO`, its `SET`, `WAIT`). */
export const isStoreOperation = (command: Command) => command.name === "EVAL";

/** The count of a login attempt from the source: its window's counter, under the route's name and the source. */
export const attemptFrom = (source: string): Match =>
	storeWrite({
		prefix,
		space: "rate-limit.attempts",
		partition: createHash("sha256").update(`login-password\n${source}`).digest("base64url"),
		operations: ["count"],
	});

const lockoutWrite = storeWrite({ prefix, space: "rate-limit.lockouts" });
const lockoutRead = storeRead({ prefix, space: "rate-limit.lockouts" });
/** Any request about an identifier's lockout: its confirmed read, or a write (a reservation, an end of its run, a hand-back). */
export const identifierLockout: Match = {
	request: (command) => lockoutRead.request(command) || lockoutWrite.request(command),
	succeeded: () => true,
};

/** The write of a new session's record: the first session write a login makes, after its attempt is counted and its identifier's run reserved. */
export const sessionRecord: Match = storeWrite({ prefix, space: "session-store.sessions" });
/** The write that indexes a session under its cookie, without which no request can reach the session. */
export const cookieIndexed: Match = storeWrite({ prefix, space: "session-store.cookies" });

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
/** The writes to an identifier's lockout: its reservations, under the route's name and the identifier's NFKC lowercase form, hashed. */
export const lockoutOf = (identifier: string): Match =>
	storeWrite({
		prefix,
		space: "rate-limit.lockouts",
		partition: sha256(
			`login-password.account\n${sha256(identifier.normalize("NFKC").toLowerCase())}`,
		),
	});

/** The run of failures a write to an identifier's lockout leaves, as the state it writes holds it. */
export const lockoutRun = (command: Command): number | undefined => {
	const run = writtenValues(command)
		.map((w) => (w.value as { run?: unknown } | null)?.run)
		.find((r) => typeof r === "number");
	return typeof run === "number" ? run : undefined;
};

/**
 * The writes of a subject's revocation boundary: its record created, or written from what it holds; not
 * the mark that confirms, before the first, that the subject holds none.
 */
export const boundaryOf = (subject: string): Match =>
	storeWrite({
		prefix,
		space: "subject-revocation-store.boundaries",
		partition: subject,
		operations: ["putIfAbsent", "replaceIf"],
	});

/** The boundaries a write of a subject's boundary puts, each a time: its sessions' and its delegations'. */
export const boundariesPut = (command: Command): number[] => {
	const put = writtenValues(command).find(
		(w) => w.key.space === "subject-revocation-store.boundaries" && w.key.name === "record",
	)?.value;
	const value = put && typeof put === "object" && "value" in put ? put.value : put;
	if (typeof value === "number") return [value];
	return value && typeof value === "object"
		? Object.values(value).filter((v): v is number => typeof v === "number")
		: [];
};

/**
 * A follower's first write after a revocation's boundary: session-lifecycle adding the subject's
 * sessions to its closings, before it closes any.
 */
export const closingAdded: Match = storeWrite({ prefix, space: "session-store.closings" });

/** The write that closes a session's record: a follower's work done for that session, past its first write. */
export const sessionClosed: Match = storeWrite({
	prefix,
	space: "session-store.sessions",
	value: (v) => (v as { state?: unknown } | null)?.state === "closed",
});
