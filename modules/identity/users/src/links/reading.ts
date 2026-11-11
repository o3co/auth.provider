import type { SubjectOf } from "@mod/erasure-extensions";

/**
 * Whose a link record written before indexing is: the subject it holds; a trace an unlink left,
 * holding no subject, is an orphan by its shape; any other shape proves nothing.
 */
export const linkSubjectOf = (value: unknown): SubjectOf => {
	const held = value as { readonly subject?: unknown } | null;
	if (held !== null && typeof held === "object" && !Array.isArray(held)) {
		if (typeof held.subject === "string" && held.subject !== "") {
			return { kind: "subject", subject: held.subject };
		}
		if (held.subject === null && Object.keys(held).length === 1) return { kind: "orphan" };
	}
	return { kind: "unreadable", reason: "a link record of another shape" };
};
