import { contract } from "@mod/kernel";
import type { AuthContext } from "@mod/session";
import type { Reauth } from "./record.ts";

export type { Reauth } from "./record.ts";

/** Re-authentications asked for one request (its parameters, each one's first value), each taken once. */
export interface Reauths {
	/** Keeps a new record for the request, from a login at `at` on, and gives its name. */
	remember(params: ReadonlyMap<string, string>, at: number, stepUp?: true): Promise<string>;
	/** Takes the named record; it counts only when this call took it and it was made for the request. */
	take(name: string | undefined, params: ReadonlyMap<string, string>): Promise<Reauth | undefined>;
	/**
	 * Whether the session's login is fresh enough for `prompt=login` and `max_age`, and its time known
	 * when one is needed; an unknown time never is. `prompt=login` and `max_age=0` are met by the
	 * taken record; any other `max_age` by the login's age now, which no record stands for.
	 */
	fresh(
		asked: {
			readonly login: boolean;
			readonly maxAgeMs: number | undefined;
			/** An essential `auth_time` was asked. */
			readonly knownTime: boolean;
		},
		context: Pick<AuthContext, "authenticatedAt" | "authenticatedAtUnknown">,
		taken: Reauth | undefined,
	): boolean;
}

/** The re-authentications, over the store the assembly wires. */
export const reauths = contract<Reauths>("reauth");
export * from "./store.ts";
