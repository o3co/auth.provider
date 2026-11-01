import { extensionPoint } from "@mod/kernel";

/**
 * Who remembers, apart from mfa's store, that a subject holds a counting factor: an outside ledger,
 * so losing the store never reads as never enrolled. Per subject its calls are linearizable, an
 * answered write lasts (a crash or a failover keeps it), and an answer is never older than the last
 * answered write; where it cannot keep that, or cannot tell, it throws Unavailable, never a default.
 */
export interface EnrollmentWitness {
	/** Whether the subject carries the mark. */
	read(subject: string): Promise<boolean>;
	/** Sets the mark to `token` unless one is set, at once; whether the mark is `token`'s after. The same token answers alike however often. */
	enroll(subject: string, token: string): Promise<boolean>;
	/** Removes the mark: after a reset clears the subject's factors, or where the call that set it finds nothing counting. */
	clear(subject: string): Promise<void>;
	/**
	 * Removes the mark where it is `token`'s, leaving any other mark, or none, as it is; the same token
	 * answers alike however often. It answers once the check and any removal are settled, and throws
	 * Unavailable where they are not. An implementation that cannot offer it leaves it out.
	 */
	withdraw?(subject: string, token: string): Promise<void>;
	/**
	 * The token the subject's mark is set to, none where it carries no mark: read as `read` is. An
	 * implementation offering it offers `withdraw` too; one that cannot leaves it out.
	 */
	markedWith?(subject: string): Promise<string | undefined>;
}

/** At most one witness: the module that asks it refuses to start with two. */
export const enrollmentWitnesses = extensionPoint<EnrollmentWitness>(
	"mfa-witness.enrollment-witnesses",
	{
		multiplicity: "many",
	},
);
