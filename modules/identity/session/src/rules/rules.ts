import { closeListed } from "./listed.ts";
import { credentialsSecondsDefault, judgedShortOf } from "./requirements.ts";

/** The rules every implementation of sessions keeps, the stand-in too, each in its one order. */
export const sessionRules = Object.freeze({
	judgedShortOf,
	credentialsSecondsDefault,
	closeListed,
});
