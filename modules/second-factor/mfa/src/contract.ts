import { extensionPoint } from "@mod/kernel";

/** A step where a user proves a factor at login; without one, a factor could never be proven. */
export interface ProofStep {
	readonly name: string;
}

/** The steps that prove factors. mfa refuses to start without at least one. */
export const proofSteps = extensionPoint<ProofStep>("mfa.proof-steps", { multiplicity: "some" });

/**
 * The name that whatever moves a subject's fence when the subject is revoked goes by among the
 * revocation's followers: a module that binds factors over revocations looks for it.
 */
export const fenceFollower = "mfa";

/** A module holding sessions to the subject's factors: what `mode` asks to use one, and a recent second factor to change credentials. */
export interface Enforcer {
	readonly name: string;
}

/** The modules holding sessions to the factors; mfa refuses to boot without one. */
export const enforcers = extensionPoint<Enforcer>("mfa.enforcers", { multiplicity: "many" });

export * from "./store.ts";
