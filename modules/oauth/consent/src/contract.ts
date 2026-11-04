import type { Client } from "@mod/clients";
import { contract } from "@mod/kernel";
import type { Session } from "@mod/session";

/** What a caller parks while it waits for the user's answer. */
export interface Asked {
	readonly range: readonly string[];
	/** Where the user goes after agreeing, and after refusing; consent does not read them. */
	readonly onAccept: string;
	readonly onDeny: string;
}

export interface Consents {
	/** The range the subject has agreed to that counts for the client now; a confirmed read. */
	grantedFor(client: Client, subject: string): Promise<readonly string[]>;
	/** Whether the subject's agreement counts for the client now, for the range; with an empty range, to anything at all. */
	coversFor(client: Client, subject: string, range: readonly string[]): Promise<boolean>;
	/** Adds to the range that counts for the client now, replacing one that does not; answers after a confirmed write. */
	grantFor(client: Client, subject: string, range: readonly string[]): Promise<void>;
	/** Whether a consent page is set to ask on; what to do without one is the caller's. */
	readonly asking: boolean;
	/**
	 * Parks a request for the session's subject and the client, answering the URL of the consent page;
	 * only while `asking`. What the user answers holds for the client as it is now.
	 */
	askFor(session: Session, client: Client, asked: Asked): Promise<string>;
}

export const consents = contract<Consents>("consent");
export {
	type ClientShown,
	canBeAgreed,
	clientCopy,
	clientSection,
	isFirstParty,
} from "./client-section.ts";
export * from "./store.ts";
