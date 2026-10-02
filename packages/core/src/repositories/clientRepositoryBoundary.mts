/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Where a `ClientRepository`'s answer enters the system. Each record it
 * answers is read once, by name, into a plain copy (`readPlainFields`), and
 * that copy is held to the registration schema (`PublicClientRecordSchema`,
 * the rules `ClientEntrySchema` holds a registered entry to). What a
 * consumer reads through the boundary is the validated copy.
 *
 * The boundary tells a refused record from an absent one
 * ({@link ValidatedClientRepository.lookupClient}): a caller that falls back
 * to another source of clients when none is registered falls back only on
 * `absent`, never in place of a record it refused. That verdict is the
 * boundary's own, never one a repository claims.
 *
 * The boundary is the outermost layer over a repository. Its `findById`
 * answers a refused record `null`, so a layer in front of it that forwards
 * that answer — a cache, a decorator, a `{ ...boundary }` copy — turns the
 * refusal into an absence, and a fallback behind that layer would serve
 * something in the refused record's place. Wrap the repository last.
 */

import type { z } from "zod";
import { auditErrorList, auditErrorText } from "../errors/envelope.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { EventLogger } from "../logging/Logger.mjs";
import type { ClientRepository, PublicClient } from "./ClientRepository.mjs";
import type { ClientRepositoryOutage } from "./clientRepositoryUnavailable.mjs";
import { PublicClientRecordSchema } from "./InMemoryClientRepository.mjs";
import { readPlainFields } from "./userSnapshot.mjs";

/**
 * The fields `PublicClient` declares, each read by name however the record
 * holds it. An entry `PublicClient` does not declare fails to compile here,
 * and a field it declares that this list misses fails to compile below.
 */
const CLIENT_RECORD_FIELDS = [
	"clientId",
	"tokenEndpointAuthMethod",
	"jwks",
	"jwksUri",
	"allowedRedirectUris",
	"allowedScopes",
	"defaultScopes",
	"allowedAudiences",
	"allowedGrantTypes",
	"postLogoutRedirectUris",
	"backchannelLogoutUri",
	"backchannelLogoutSessionRequired",
	"frontchannelLogoutUri",
	"frontchannelLogoutSessionRequired",
	"allowedAzpForFederationToken",
	"allowedFederationGrantConnections",
	"federationGrantRedirectUris",
	"senderConstrained",
	"firstParty",
	"clientName",
	"clientUri",
	"allowPlainPkce",
] as const satisfies readonly (keyof PublicClient)[];

type UnreadClientField = Exclude<keyof PublicClient, (typeof CLIENT_RECORD_FIELDS)[number]>;
const everyDeclaredFieldRead: [UnreadClientField] extends [never] ? true : UnreadClientField = true;
void everyDeclaredFieldRead;

/** The schema's answer is a `PublicClient`: a field it holds to another type fails to compile. */
const answersPublicClient = (client: z.output<typeof PublicClientRecordSchema>) =>
	client satisfies PublicClient;
void answersPublicClient;

/**
 * The schema judges exactly the fields read: one it does not know would be
 * refused as unrecognised on every record, and one it knows but this list
 * misses would never reach it. Either fails to compile here.
 */
type ClientRecordField = (typeof CLIENT_RECORD_FIELDS)[number];
type SchemaField = keyof z.output<typeof PublicClientRecordSchema>;
type MismatchedField =
	| Exclude<SchemaField, ClientRecordField>
	| Exclude<ClientRecordField, SchemaField>;
const schemaJudgesEveryFieldRead: [MismatchedField] extends [never] ? true : MismatchedField = true;
void schemaJudgesEveryFieldRead;

/** What {@link readClientRecord} answers: the validated copy, or why the record is refused. */
type ClientRecordReading =
	| { readonly ok: true; readonly client: PublicClient }
	| { readonly ok: false; readonly reasons: readonly string[] };

/**
 * `record`, answered for `clientId`, as the plain validated copy every
 * consumer reads: each field `PublicClient` declares read once, by name,
 * however the record holds it (own data, a prototype getter, an ORM entity, a
 * Proxy), and nothing else of it — never a `clientSecret` beside them. That
 * copy is frozen at every depth before it is parsed; what is answered is the
 * schema's parse of it, its defaults filled: a fresh object per lookup that
 * shares nothing with the record or with another answer, and is not frozen.
 * Its `clientId` must be the id that was looked up, and an id no request
 * could name (`isWellFormedClientId`) is refused, as at boot.
 *
 * Refused, with each reason: a record that is not an object, a field holding
 * what JSON does not hold as it is, a field the schema refuses, an id that
 * is not `clientId`. A read that throws is let through as it was thrown.
 */
function readClientRecord(record: object, clientId: string): ClientRecordReading {
	if (Array.isArray(record)) return { ok: false, reasons: ["not an object"] };
	const plain = readPlainFields(record, CLIENT_RECORD_FIELDS);
	if (!plain.ok) return { ok: false, reasons: [`${plain.field}: not plain data`] };
	const parsed = PublicClientRecordSchema.safeParse(plain.copy);
	if (!parsed.success) {
		return {
			ok: false,
			reasons: parsed.error.issues.map(
				(issue) => `${issue.path.map(String).join(".") || "record"}: ${issue.message}`,
			),
		};
	}
	if (parsed.data.clientId !== clientId) {
		return { ok: false, reasons: ["clientId: not the id that was looked up"] };
	}
	return { ok: true, client: parsed.data };
}

/** How many reasons a refusal's log line keeps. */
const LOGGED_REASONS_MAX = 10;

/**
 * What {@link ValidatedClientRepository.lookupClient} answers for an id:
 *
 * - `found`: the record, read and validated, as `findById` answers it;
 * - `refused`: the repository answered a record and the boundary refused it,
 *   with each reason. The client is unknown, and nothing stands in for it;
 * - `absent`: the repository answered no record (`null` or `undefined`).
 */
export type ClientLookup =
	| { readonly outcome: "found"; readonly client: PublicClient }
	| { readonly outcome: "refused"; readonly reasons: readonly string[] }
	| { readonly outcome: "absent" };

/**
 * A `ClientRepository` behind core's boundary. `findById` and `authenticate`
 * keep the port's meaning (a client, or `null` for an unknown one) and answer
 * only validated records; `lookupClient` says which unknown it is.
 */
export interface ValidatedClientRepository extends ClientRepository {
	/**
	 * The repository's `findById` answer for `clientId`, read and judged once:
	 * found, refused or absent. A read that throws is let through as it was
	 * thrown.
	 */
	lookupClient(clientId: string): Promise<ClientLookup>;
}

/** What {@link validatedClientRepository} takes beside the repository. */
export interface ClientRepositoryBoundaryOptions {
	/**
	 * Where a refused record is said. Default: `consoleLogger`. Ignored when
	 * the repository is already a boundary, which keeps its own.
	 */
	readonly logger?: Pick<EventLogger, "warn">;
}

/** The boundaries this module built, so one is never wrapped again. */
const boundaries = new WeakSet<ClientRepository>();

/**
 * `inner` behind the boundary: each record `findById` or `authenticate`
 * answers is read once into a plain copy and held to the registration
 * schema, and the copy is what is answered.
 *
 * - A record that fails is refused: `lookupClient` answers `refused`, and
 *   `findById` and `authenticate` answer `null`, as for an unknown client.
 *   Each refusal writes one `client_record_refused` warn: the `step`
 *   (`find` or `authenticate`), the client id sanitised and capped, and the
 *   reasons, at most ten, each sanitised and capped (`reasonCount` when
 *   more). The record itself is never logged.
 * - `null` or `undefined` is no record: `absent`, or `null`, silently.
 * - A throw, the repository's or a field read's, is let through as it was
 *   thrown: the store's outage, which each caller answers as one (`503`;
 *   the logout routes go on without the redirect).
 *
 * The boundary must be the outermost layer: anything that forwards its
 * `findById` hides a refusal as an absence (see the file header). A boundary
 * handed to it is answered as it is, never wrapped twice, so it keeps the
 * logger it was first built with; `options` are not read. The boundary is
 * disposable when `inner` is, and disposing it disposes `inner`.
 *
 * The reasons a refusal logs name each field and the rule it broke, and some
 * quote the field's value (a refused redirect URI, a scope outside the
 * allowed ones): registration data, none of it secret. The record object is
 * never logged.
 */
export function validatedClientRepository(
	inner: ClientRepository,
	options: ClientRepositoryBoundaryOptions = {},
): ValidatedClientRepository {
	if (boundaries.has(inner)) return inner as ValidatedClientRepository;
	const logger = options.logger ?? consoleLogger;
	const judge = (
		step: ClientRepositoryOutage["step"],
		clientId: string,
		record: PublicClient | null | undefined,
	): ClientLookup => {
		if (record === null || record === undefined) return { outcome: "absent" };
		const reading =
			typeof record === "object"
				? readClientRecord(record, clientId)
				: ({ ok: false, reasons: ["not an object"] } as const);
		if (reading.ok) return { outcome: "found", client: reading.client };
		logger.warn(
			{
				step,
				clientId: auditErrorText(clientId),
				reasons: auditErrorList(reading.reasons, LOGGED_REASONS_MAX),
				...(reading.reasons.length > LOGGED_REASONS_MAX
					? { reasonCount: reading.reasons.length }
					: {}),
			},
			"client_record_refused",
		);
		return { outcome: "refused", reasons: reading.reasons };
	};
	const clientOf = (lookup: ClientLookup): PublicClient | null =>
		lookup.outcome === "found" ? lookup.client : null;
	const lookupClient = async (clientId: string): Promise<ClientLookup> =>
		judge("find", clientId, await inner.findById(clientId));
	const boundary: ValidatedClientRepository = {
		lookupClient,
		findById: async (clientId) => clientOf(await lookupClient(clientId)),
		authenticate: async (clientId, secret) =>
			clientOf(judge("authenticate", clientId, await inner.authenticate(clientId, secret))),
	};
	const dispose = (inner as { [Symbol.asyncDispose]?: unknown })[Symbol.asyncDispose];
	const answered: ValidatedClientRepository & Partial<AsyncDisposable> =
		typeof dispose === "function"
			? {
					...boundary,
					[Symbol.asyncDispose]: async () => {
						await dispose.call(inner);
					},
				}
			: boundary;
	boundaries.add(answered);
	return answered;
}
