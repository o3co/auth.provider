import { createHash } from "node:crypto";
import { type Command, type Match, storeWrite } from "@mod/conformance/testing";

// The store's own names a scene matches its writes by: the space, its records' names and fields, and
// the operations, as webauthn-store and records keep them. Nothing else in the area names them.

/** The deployment's `redis.prefix`: the adapter's own, as no scene sets one. */
export const prefix = "store";
const challenges = "webauthn-store.challenges";

/** Whether a command is a store call: the adapter sends each as a script. */
export const isStoreCall = (command: Command) => command.name === "EVAL";

/** A challenge's record's partition: its name, made from the challenge as webauthn-store's records make it. */
const partitionOf = (challenge: string) =>
	`1.${createHash("sha256").update(`${challenges}\n${challenge}`).digest("base64url")}`;

/**
 * The write that takes the challenge: its record turned taken. It is sent, and succeeds, on every
 * assertion of a challenge still kept, taken or not, so its successes do not count the challenge's uses.
 */
export const takeOf = (challenge: string): Match =>
	storeWrite({
		prefix,
		space: challenges,
		partition: partitionOf(challenge),
		name: "record",
		operations: ["replaceIf"],
		value: (v) => (v as { taken?: unknown }).taken === true,
	});
