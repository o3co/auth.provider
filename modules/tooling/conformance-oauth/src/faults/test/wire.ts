import { type Match, storeRead, storeWrite } from "@mod/conformance/testing";
import { prefix } from "./faults.ts";

// The store's own names the area's scenes match on, kept in this one file: the request windows'
// space and operation, and the spaces the grant's decision reads and writes.

/** The token endpoint's count of a request by its source, in the request windows. */
export const requestCounted: Match = storeWrite({
	prefix,
	space: "rate-limit.windows",
	operations: ["count"],
});
/** What the grant's decision sends once a request passed its limit: the boundary read and the spend. */
export const grantDecision: readonly Match[] = [
	storeRead({ prefix, space: "subject-revocation-store.boundaries" }),
	storeWrite({ prefix, space: "jwt-bearer-store.spent", operations: ["putIfAbsent"] }),
];
