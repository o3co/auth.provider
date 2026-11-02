import type { Client } from "@mod/clients";
import { contract } from "@mod/kernel";
import type { Session } from "@mod/session";

/** What a caller parks while it waits for the user's answer. */
export interface Asked {
	readonly clientId: string;
	readonly range: readonly string[];
	/** Where the user goes after agreeing, and after refusing; consent does not read them. */
	readonly onAccept: string;
	readonly onDeny: string;
}

export interface Consents {
	/** The range the subject has agreed to for the client; a confirmed read. */
	granted(clientId: string, subject: string): Promise<readonly string[]>;
	/** Whether the subject has agreed to the client for the range; with an empty range, to anything at all. */
	covers(clientId: string, subject: string, range: readonly string[]): Promise<boolean>;
	/** Adds to the subject's range for the client; answers after a confirmed write. */
	grant(clientId: string, subject: string, range: readonly string[]): Promise<void>;
	/** The range the subject has agreed to that counts for the client now; a confirmed read. */
	grantedFor(client: Client, subject: string): Promise<readonly string[]>;
	/** Whether the subject's agreement counts for the client now, for the range; with an empty range, to anything at all. */
	coversFor(client: Client, subject: string, range: readonly string[]): Promise<boolean>;
	/** Adds to the range that counts for the client now, replacing one that does not; answers after a confirmed write. */
	grantFor(client: Client, subject: string, range: readonly string[]): Promise<void>;
	/** As `ask`, for this client: what the user answers is held to what the client is now. */
	askFor(session: Session, client: Client, asked: Omit<Asked, "clientId">): Promise<string>;
	/** Whether a consent page is set to ask on; what to do without one is the caller's. */
	readonly asking: boolean;
	/** Parks a request for the session's subject, answering the URL of the consent page; only while `asking`. */
	ask(session: Session, asked: Asked): Promise<string>;
}

export const consents = contract<Consents>("consent");
export { type ClientShown, clientCopy, clientSection, isFirstParty } from "./client-section.ts";
export * from "./store.ts";
