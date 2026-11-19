import { type Eraser, ownerStopped } from "@mod/erasure-extensions";
import type { RoundTripStore } from "../store.ts";

/**
 * Frozen from v0.19.1 (tag v0.19.1): a 0.19 link's round trip, the only one that carried a subject,
 * lives at most `transaction-lifetime`'s ceiling, 3600 s (`modules/upstream-login/federation/src/section.ts`);
 * federation-grants' connect round trips at most `connect-lifetime`'s, 3600 s
 * (`modules/delegation/federation-grants/src/section.ts`). The bound is the callers', so `begin` caps none.
 */
const legacyBoundSeconds = 3600;

const remains = `a round trip remains, which a 0.19 instance may have begun holding a subject; run again once the longest lifetime this deployment's callers give has passed since the provider's connections were locked out (at most ${legacyBoundSeconds.toLocaleString("en")} s for 0.19.1's own callers); a stop past that means something still begins round trips`;

/**
 * upstream-round-trip's eraser, `upstream-round-trip`: its space holds no subject's data, so it erases
 * nothing, and its migration stops while any round trip record remains, never opening one: a 0.19
 * round trip may carry a subject's data. `erasable` only where the store offers `walk`. It reports no space, so a run cut
 * short throws the signal's reason. TODO(0.22): goes with the 0.19 round trips.
 */
export function roundTripEraser(store: Pick<RoundTripStore, "walk">): Eraser {
	const none = async (signal: AbortSignal) => {
		signal.throwIfAborted();
		return { reports: [], logoutGaps: 0 };
	};
	return {
		name: "upstream-round-trip",
		erasable: store.walk !== undefined,
		online: (_subject, signal) => none(signal),
		window: (_subjects, _walk, signal) => none(signal),
		migrate: async (walk, signal) => {
			signal.throwIfAborted();
			if (!store.walk) return [];
			const walked = await store.walk(walk, () => false, signal);
			if (walked.kind === "walked") return [];
			if (walked.kind === "stopped") return [ownerStopped(remains)];
			if (walked.reason === "aborted") throw signal.reason;
			// A walk that did not finish proves nothing of the records it did not reach.
			return [ownerStopped(`the round trips' walk did not finish (${walked.reason}); run again`)];
		},
	};
}
