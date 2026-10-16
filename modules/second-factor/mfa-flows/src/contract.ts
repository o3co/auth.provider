import { contract } from "@mod/kernel";

/** An operator's reset of a subject's second factors, for the embedder that has verified who asks. */
export interface MfaReset {
	/** Answers how many factors went; rejects as unavailable when a step cannot be done, and running it again finishes it. */
	reset(subject: string, options?: { readonly requestedBy?: string }): Promise<number>;
}

export const mfaReset = contract<MfaReset>("mfa-flows.reset");

export * from "./store.ts";
