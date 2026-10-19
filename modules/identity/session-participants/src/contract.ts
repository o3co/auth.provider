import { extensionPoint } from "@mod/kernel";
import type { Session } from "@mod/session";

/** Work done when a session closes, contributed by the module that owns it. */
export interface Participant {
	readonly name: string;
	closing(session: Session): Promise<void>;
}

export const participants = extensionPoint<Participant>("session-participants.participants", {
	multiplicity: "keyed",
	keyOf: (participant) => participant.name,
});
