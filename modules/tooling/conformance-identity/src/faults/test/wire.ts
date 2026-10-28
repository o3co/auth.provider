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
/** Every store operation. */
export const storeOperations: Match = { request: isStoreOperation, succeeded: () => true };

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
