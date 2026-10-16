import { extensionPoint } from "@mod/kernel";

/** Where the browser goes back after a logout, and the state it carries. */
export interface LogoutReturn {
	readonly postLogoutRedirectUri?: string;
	readonly state?: string;
}

/** Ends the upstream session a session came from, before the logout returns to the client. */
export interface UpstreamEnd {
	readonly name: string;
	/** The upstream's end of session for the session, carrying the return; none where it has none. Asked before the session closes. */
	at(session: string, back: LogoutReturn): Promise<string | undefined>;
}

/** At most one; two or more refuse boot. */
export const upstreamEnds = extensionPoint<UpstreamEnd>("rp-logout.upstream-ends", {
	multiplicity: "many",
});

export * from "./store.ts";
