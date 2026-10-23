import { type Audit, declaredAudit } from "@mod/audit";
import type { HttpRequest } from "@mod/http";
import { contract, extensionPoint } from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import type { StandardSchemaV1 } from "@standard-schema/spec";
import events from "./audit-events.ts";

/** A metadata section a module adds to client records; absent sections take the schema's default. */
export interface Section<T> {
	readonly name: string;
	readonly schema: StandardSchemaV1<unknown, T>;
	/**
	 * Checks a registered client's value, after the schema, at boot, with the client that holds it;
	 * a reason refuses boot. The reason goes into the refusal unchanged, so it must never hold a
	 * configuration value.
	 */
	checkAtBoot?(value: T, client: Client): string | undefined;
}

export interface Client {
	readonly id: string;
	readonly kind: "public" | "confidential";
	readonly method: string;
	/** True when the operator registered the client in the settings, rather than a source naming it. */
	readonly registered: boolean;
	/** The client's value of a contributed section; throws for a section no module contributed. */
	section<T>(section: Section<T>): T;
}

/** A record as a source returns it, before its sections are checked. */
export interface ClientRecord {
	readonly id: string;
	readonly kind: "public" | "confidential";
	readonly method: string;
	readonly sections: Readonly<Record<string, unknown>>;
}

/** Where a record fails, from its root (`method`, `sections.consent.uri`); never a value. */
export interface RecordRefusal {
	readonly path: string;
}

export interface ClientSource {
	find(id: string): Promise<ClientRecord | undefined>;
}

export interface AuthMethod {
	readonly name: string;
	/** The JWS algorithms its credentials may be signed with, for a method whose credentials are signed. */
	readonly signingAlgorithms?: readonly string[];
	/** The WWW-Authenticate challenge to send when this method's credentials are refused. */
	readonly challenge?: string;
	/** The client id the request claims through this method, if it uses this method at all. */
	claimed(request: HttpRequest): string | undefined;
	/** Whether the request carries this method's credentials only in part, or in a form it does not take. */
	malformed?(request: HttpRequest): boolean;
	verify(request: HttpRequest, client: Client): Promise<boolean>;
	/** The work a verify would cost, done for a request refused before it (no such client, say), so the time tells nothing. */
	decoy?(request: HttpRequest): Promise<void>;
}

export type Authentication =
	| {
			readonly kind: "authenticated";
			readonly client: Client;
			/** Challenges for a later 401 to this client: its method's, or every method's when its method has none. */
			readonly challenges: readonly string[];
	  }
	| {
			readonly kind: "refused";
			readonly reason:
				| "no_credentials"
				| "multiple_methods"
				| "malformed_credentials"
				| "unknown_client"
				| "wrong_method"
				| "bad_credentials"
				| "invalid_record";
			/** Challenges for the response: the tried method's, or every method's when none was tried. */
			readonly challenges: readonly string[];
	  };

export interface Clients {
	find(id: string): Promise<Client | undefined>;
	/**
	 * Checks a record as `find` holds a source's: the rule for a registered one, a known method and
	 * each section's schema. Answers where each part fails, nothing when it fits; rejects when a
	 * schema throws.
	 */
	checkRecord(record: ClientRecord): Promise<readonly RecordRefusal[] | undefined>;
	authenticate(request: HttpRequest): Promise<Authentication>;
	/**
	 * The clients the operator registered, in the settings' order: the `i`th is at
	 * `clients.registered.<i>`, where a boot check names it by its place, never its id.
	 */
	registered(): readonly Client[];
	/** The names of the ways a client can authenticate here, built in and contributed. */
	methods(): readonly string[];
	/** The algorithms those methods take signed credentials in, each once. */
	signingAlgorithms(): readonly string[];
}

export const clients = contract<Clients>("clients");

export const authMethods = extensionPoint<AuthMethod>("clients.auth-methods", {
	multiplicity: "keyed",
	keyOf: (method) => method.name,
});

export const clientSources = extensionPoint<ClientSource>("clients.sources", {
	multiplicity: "many",
});

export const metadataSections = extensionPoint<Section<unknown>>("clients.metadata-sections", {
	multiplicity: "keyed",
	keyOf: (section) => section.name,
});

/** Records a refused authentication on the caller's audit, by its reason and the source alone. */
export function recordRefusedAuthentication(
	audit: Pick<Audit, "record">,
	request: HttpRequest,
	refused: Extract<Authentication, { kind: "refused" }>,
): void {
	const source = determinedSource(request);
	declaredAudit(audit, events).record("client.authentication.failure", {
		attributes: { ...(source === undefined ? {} : { source }), reason: refused.reason },
	});
}
