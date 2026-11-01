import type { IntentRef } from "../browser.ts";
import type { Credentials, Grant, Intent } from "../grant/grant.ts";

/** A ref as the browser half holds it: the grant and its intent as read. */
export interface Found {
	readonly grant: Grant;
	readonly intent: Intent;
}
export const refOf = (found: Found) => Object.freeze({ ...found }) as unknown as IntentRef;
export const foundOf = (ref: IntentRef) => ref as unknown as Found;
/** Tokens as judged fit to hold: the credentials read from them, and when. */
export interface Judged {
	readonly credentials: Credentials;
	readonly now: number;
}
