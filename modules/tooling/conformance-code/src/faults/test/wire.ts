import { createHash } from "node:crypto";
import {
	type Command,
	type Execution,
	keysOf,
	type Match,
	type StoreKey,
	storeRead,
	storeWrite,
	writtenValues,
} from "@mod/conformance/testing";
import type { Code } from "./faults.ts";

// The one place the area's fault scenes name what the store keeps: its spaces, partitions, operations
// and the fields of its records, as subject-revocation, session-lifecycle and the code flow's stores
// write them. A scene says what it watches by these, never by the names themselves.

/** The deployment's `redis.prefix`: the adapter's own, as no scene sets one. */
export const prefix = "store";

/** Any write of a code's record. */
export const codeRecord = storeWrite({ prefix, space: "code-grant-store.codes" });
/** The write that keeps a new code: the record a code is issued with. */
export const codeKept = storeWrite({
	prefix,
	space: "code-grant-store.codes",
	operations: ["putIfAbsent"],
});
/** A read of a code's record, which a redemption waits on first. */
export const codeRead = storeRead({ prefix, space: "code-grant-store.codes" });
/** The mark that confirms a read of a code's record, written beside it: the code's read, confirmed. */
export const codeReadSettled = storeWrite({
	prefix,
	space: "code-grant-store.codes",
	name: "settled",
});
/** The read of the browser's session behind its cookie, which an authorization waits on first. */
export const cookieRead = storeRead({ prefix, space: "session-store.cookies" });

/** A code's record as the store holds it: the fields a scene tells its writes by. */
interface CodeRecord {
	readonly state?: unknown;
	readonly challenge?: unknown;
	readonly token?: unknown;
	readonly void?: unknown;
}
const codeWrite = (challenge: string, is: (r: CodeRecord) => boolean): Match =>
	storeWrite({
		prefix,
		space: "code-grant-store.codes",
		operations: ["replaceIf"],
		value: (v) => (v as CodeRecord).challenge === challenge && is(v as CodeRecord),
	});

/** The write that uses the code up: its record turned consumed, before any token is noted on it. */
export const codeUse = (c: Code) =>
	codeWrite(c.challenge, (r) => r.state === "consumed" && r.token === undefined && !r.void);

/** The write that notes, on the used code, the token issued for it. */
export const codeNoted = (c: Code) =>
	codeWrite(c.challenge, (r) => r.state === "consumed" && r.token !== undefined && !r.void);

/** A refresh token's family, which names its record, and its secret. */
const partsOf = (token: string) => {
	const [family = "", secret = ""] = token.split(".");
	return { family, secret };
};

/**
 * The write that rotates a family from `token`: its record's current secret moved off the token's,
 * the family still live; a revocation, which keeps no current secret, is none.
 */
export function rotationFrom(token: string): Match {
	const { family, secret } = partsOf(token);
	const presented = createHash("sha256").update(secret).digest("base64url");
	return storeWrite({
		prefix,
		space: "refresh-store.families",
		partition: family,
		operations: ["replaceIf"],
		value: (v) => {
			const current = (v as { current?: unknown }).current;
			return typeof current === "string" && current !== presented;
		},
	});
}

/** Whether a call is on a refresh family's record. */
export const onFamilies = (command: Command) =>
	keysOf(command).some((k) => k.space === "refresh-store.families");

const state = (v: unknown) => (v as { state?: unknown } | null)?.state;
/** A handle added to the closings: a shard's list holding one, as a scene starts with none pending. */
export const added = storeWrite({
	prefix,
	space: "session-store.closings",
	value: (v) => Array.isArray(v) && v.length > 0,
});
/** The session's record written as `closing`, or as `closed`. */
export const recordAs = (s: "closing" | "closed", handle?: string): Match =>
	storeWrite({
		prefix,
		space: "session-store.sessions",
		...(handle ? { partition: handle } : {}),
		value: (v) => state(v) === s,
	});
/** The participant's write that puts the session's access token, by its `jti`, on the revoked list. */
export const revocationOf = (jti: string) =>
	storeWrite({
		prefix,
		space: "tokens-store.revoked",
		partition: jti,
		operations: ["putIfAbsent"],
	});

/** A close a logout began: its session's handle, the closings' shard it was added to, and its token's `jti`. */
export interface Closing {
	readonly handle: string;
	readonly shard: StoreKey;
	readonly jti: string;
}

/** The close an add wrote, the one item of its shard's list, for the session whose token is `jti`. */
export function closingOf(add: Execution, jti: string): Closing {
	const [written] = writtenValues(add.command);
	const list = written?.value;
	if (!written || !Array.isArray(list) || list.length !== 1 || typeof list[0] !== "string")
		throw new Error(`the closings held more than the one close: ${JSON.stringify(list)}`);
	return { handle: list[0], shard: written.key, jti };
}

/** The close's shard written without its handle: the close is done. */
export const doneWith = (c: Closing) =>
	storeWrite({
		prefix,
		space: c.shard.space,
		partition: c.shard.partition,
		name: c.shard.name,
		value: (v) => Array.isArray(v) && !v.includes(c.handle),
	});

/** A store operation: the Redis adapter runs each as a script. */
export const isStoreOperation = (command: Command) => command.name === "EVAL";

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

/** The write that creates a subject's first boundary; a revocation that finds one held writes it from that instead. */
export const boundaryCreated = (subject: string): Match =>
	storeWrite({
		prefix,
		space: "subject-revocation-store.boundaries",
		partition: subject,
		operations: ["putIfAbsent"],
	});

/**
 * A follower's first write after a revocation's boundary: session-lifecycle adding the subject's
 * sessions to its closings, before it closes any.
 */
export const closingAdded: Match = storeWrite({ prefix, space: "session-store.closings" });
