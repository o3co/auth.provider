import { contract } from "@mod/kernel";

/** Where the browser goes back after the upstream ends its session, and the state it carries. */
export interface EndSessionReturn {
	readonly postLogoutRedirectUri?: string;
	readonly state?: string;
}

export interface UpstreamEndSessions {
	/** The end of session of the first upstream the session logged in through; none where it has none. Asked before the session closes, which forgets its upstream tokens. */
	of(session: string, back: EndSessionReturn): Promise<string | undefined>;
}

export const upstreamEndSessions = contract<UpstreamEndSessions>(
	"federation-tokens.upstream-end-sessions",
);

export * from "./store.ts";
