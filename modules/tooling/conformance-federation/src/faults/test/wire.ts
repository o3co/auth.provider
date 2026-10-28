import { type Command, type Match, storeWrite, writtenValues } from "@mod/conformance/testing";

// The store's own names a scene matches its writes by: the spaces and partitions subject-revocation
// and session-lifecycle write. Nothing else in the area names them.

/** The deployment's `redis.prefix`: the adapter's own, as no scene sets one. */
export const prefix = "store";

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
 * sessions to its closings, before it closes any, and before federation-grants' follower runs.
 */
export const closingAdded: Match = storeWrite({ prefix, space: "session-store.closings" });

/** A write to a grant's record: among them a read ending a grant its subject's revocation covers (`backstop`). */
export const grantWritten: Match = storeWrite({ prefix, space: "federation-grants-store.grants" });

/** The boundaries a write of a subject's boundary puts: `sessions` and, once a revocation moved it, `delegations`. */
export const boundariesPut = (command: Command): { sessions?: unknown; delegations?: unknown } => {
	const put = writtenValues(command).find(
		(w) => w.key.space === "subject-revocation-store.boundaries" && w.key.name === "record",
	)?.value as { sessions?: unknown; delegations?: unknown; value?: unknown } | undefined;
	const value = (put && typeof put === "object" && "value" in put ? put.value : put) as
		| { sessions?: unknown; delegations?: unknown }
		| undefined;
	return value ?? {};
};
