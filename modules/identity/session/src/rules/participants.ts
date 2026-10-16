import type { Participant, Session } from "../contract.ts";

/** Calls the participants one at a time, in the order given; answers each that failed, none when all finished. */
export async function failedParticipants(
	participants: readonly Participant[],
	session: Session,
): Promise<readonly { readonly participant: string; readonly kind: string }[]> {
	const failed: { participant: string; kind: string }[] = [];
	for (const participant of participants) {
		try {
			await participant.closing(session);
		} catch (error) {
			// A failure is answered by kind only, and does not stop the rest.
			const kind = error instanceof Error ? error.name : typeof error;
			failed.push({ participant: participant.name, kind });
		}
	}
	return failed;
}
