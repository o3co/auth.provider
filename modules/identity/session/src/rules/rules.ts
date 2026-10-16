import { closeListed } from "./listed.ts";
import { failedParticipants } from "./participants.ts";
import { credentialsSecondsDefault, entryShortOf, firstShortOf } from "./requirements.ts";

/** The rules every implementation of sessions keeps, the stand-in too, each in its one order. */
export const sessionRules = Object.freeze({
	failedParticipants,
	firstShortOf,
	entryShortOf,
	credentialsSecondsDefault,
	closeListed,
});
