import { createHash } from "node:crypto";
import { type Command, type Match, storeWrite } from "@mod/conformance/testing";

// The store's own names a scene matches its writes by: the space, its records' fields, the
// operations, and how a recovery code is kept, as mfa-store, mfa and mfa-recovery keep them. Nothing
// else in the area names them.

/** The deployment's `redis.prefix`: the adapter's own, as no scene sets one. */
export const prefix = "store";

/** Whether a command is a store call: the adapter sends each as a script. */
export const isStoreCall = (command: Command) => command.name === "EVAL";

/** A recovery code as mfa-recovery keeps it: read whatever the case and hyphens, unsalted. */
const digest = (code: string) =>
	createHash("sha256").update(code.toUpperCase().replaceAll("-", "")).digest("base64url");

/** A subject's factor list as the store holds it: the fields a scene tells its writes by. */
interface FactorList {
	readonly factors?: readonly { readonly kind?: unknown; readonly state?: unknown }[];
}

/**
 * The write that uses the recovery code up: the subject's factor list with the code's digest last
 * among the recovery codes used. A later code's use puts its own last, so it is never this one's; a
 * rewrite of the list for another reason (another factor's state) would match too, and no scene
 * makes one.
 */
export const useOf = (code: string): Match =>
	storeWrite({
		prefix,
		space: "mfa-store.factors",
		operations: ["replaceIf"],
		value: (v) =>
			((v as FactorList).factors ?? []).some(
				(f) =>
					f.kind === "recovery_code" && Array.isArray(f.state) && f.state.at(-1) === digest(code),
			),
	});
