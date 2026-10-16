import type { Log } from "@mod/kernel";
import type { Upstreams } from "@mod/upstreams";
import type { EndSessionReturn } from "./contract.ts";

/** The upstream's end of session with the hint and return, or none when it has none or cannot build one (warned by its kind). */
export function endSessionAt(
	upstreams: Upstreams,
	idp: string,
	idToken: string | undefined,
	back: EndSessionReturn,
	log: Pick<Log, "warn">,
): string | undefined {
	try {
		return upstreams.of(idp)?.endSession?.({
			...(idToken ? { idTokenHint: idToken } : {}),
			...(back.postLogoutRedirectUri ? { postLogoutRedirectUri: back.postLogoutRedirectUri } : {}),
			...(back.state === undefined ? {} : { state: back.state }),
		});
	} catch (error) {
		const kind = error instanceof Error ? error.name : typeof error;
		log.warn("federation-tokens.end_session_failed", { idp, kind });
		return undefined;
	}
}
