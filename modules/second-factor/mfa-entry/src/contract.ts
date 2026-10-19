import { contract } from "@mod/kernel";
import type { AuthContext } from "@mod/session";

/** What a session's second factor stands for. */
export interface SecondFactors {
	/** Whether the session proved a second factor within `session`'s recent window; a recent sign-in never stands for one. */
	provenRecently(context: AuthContext): boolean;
}

export const secondFactors = contract<SecondFactors>("mfa-entry.second-factors");
