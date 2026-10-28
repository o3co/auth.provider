import { type Command, type Match, storeWrite } from "@mod/conformance/testing";
import { prefix } from "./faults.ts";

// The names the revocation boundary's scenes add of the store's inside: the spaces and partitions
// subject-revocation and session-lifecycle write. The code flow's own (the prefix, a code's and a refresh
// token's writes) are still in faults.ts until they are gathered here.

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
