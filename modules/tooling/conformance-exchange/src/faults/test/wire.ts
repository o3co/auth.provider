import { createHash } from "node:crypto";
import { type Command, type Match, storeWrite, writtenValues } from "@mod/conformance/testing";

// The store's own names a scene matches its writes by: the spaces and partitions subject-revocation,
// session-lifecycle and exchange-id-tokens write. Nothing else in the area names them.

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

/**
 * The write that takes an Apple id_token, by either grant: its record created under its kind and the
 * SHA-256 of its header and payload.
 */
export const takenOf = (idToken: string): Match =>
	storeWrite({
		prefix,
		space: "exchange-id-tokens-store.used",
		partition: `apple/${createHash("sha256")
			.update(idToken.split(".").slice(0, 2).join("."))
			.digest("base64url")}`,
		operations: ["putIfAbsent"],
	});
