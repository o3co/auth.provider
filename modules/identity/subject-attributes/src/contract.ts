import { contract } from "@mod/kernel";
import { loginSource, type SourcedAttributes } from "@mod/login-attributes";

/** Where an answer's attributes came from: `users`, or a session's login under the source it kept. */
export type AttributesSource = "users" | `session:${string}`;

export type AttributesAnswer =
	/** By users' names (`userAttribute`), each value as its source holds it. */
	| {
			readonly kind: "known";
			readonly source: AttributesSource;
			/** Present when users stands behind these attributes; absent, nobody vouches for them. */
			readonly vouched?: true;
			readonly attributes: Readonly<Record<string, unknown>>;
	  }
	/** Neither users nor the session can say. */
	| { readonly kind: "unknown" };

export interface SubjectAttributes {
	/**
	 * The subject's attributes from one source, never mixed: users when it answers for the subject
	 * (a subject with no user: no attributes, from users), else the login attributes of the session
	 * `handle` names when it is open and the subject's. Vouched when users states them: users' answer,
	 * or a login kept under the source `users`; never an upstream's login.
	 * Throws Unavailable when users or session fails.
	 */
	of(subject: string, handle?: string): Promise<AttributesAnswer>;
}

export const subjectAttributes = contract<SubjectAttributes>("subject-attributes");

/**
 * Whether `users` stands behind a login's attributes: only a login that read users' ledger does; an
 * upstream's word is its own. The one rule, for a session's login here and for a login still held.
 */
export const vouches = (attributes: Pick<SourcedAttributes, "source">): boolean =>
	attributes.source === loginSource.users;
