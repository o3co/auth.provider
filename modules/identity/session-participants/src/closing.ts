import type { ClosingParticipants } from "@mod/session";
import type { Participant } from "./contract.ts";

/** Calls the participants one at a time, in the order given; answers each that failed, none when all finished. */
export function closingOf(given: readonly Participant[]): ClosingParticipants {
	return {
		closing: async (session) => {
			const failed: { participant: string; kind: string }[] = [];
			for (const participant of given) {
				try {
					await participant.closing(session);
				} catch (error) {
					// A failure is answered by kind only, and does not stop the rest.
					const kind = error instanceof Error ? error.name : typeof error;
					failed.push({ participant: participant.name, kind });
				}
			}
			return failed;
		},
	};
}
