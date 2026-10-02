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
 * - **What is read.** Exactly the fields `PublicClient` declares, each once,
 *   by name, however the record holds it (own data, a prototype getter, an
 *   ORM entity, an Array subclass, a Proxy); never `clientSecret`, and
 *   nothing else of the record. The field list is checked against
 *   `PublicClient` and against the schema, both ways, at compile time.
 * - **What is held.** The registration's fields and rules with the id in
 *   place of the secret, the defaults filled. The record's `clientId` must be
 *   the id looked up, exactly, and one no request could name
 *   (`isWellFormedClientId`) is refused, as at boot.
 * - **What is answered.** The parse, copied once more by the same copier, so
 *   it is frozen at every depth and shares nothing with the record or with
 *   another answer.
 * - **What a refusal says.** One `client_record_refused` warn with the step,
 *   the client id sanitised and capped, and the reasons. A reason names the
 *   field, an entry's position (`allowedRedirectUris[2]`) and the rule it
 *   broke, never a URI: a URI's query can carry a credential registered by
 *   mistake; a default scope outside the allowed ones is named by its
 *   position too. A rule about a scheme or a host names that scheme or host,
 *   and the reserved parameter and JWK member names come from fixed lists.
 *   The record object is never logged.
 *
 * - **What a refused lookup answers.** `findById` and `authenticate` reject
 *   with a {@link ClientRecordRefusedError}, never `null`: a refusal is the
 *   rejection itself, recognised by its brand (`isClientRecordRefused`), so
 *   it survives any layer that lets rejections through — a cache, a
 *   decorator, a `{ ...boundary }` copy, another boundary — and no fallback
 *   behind such a layer can read it as an absent client. A caller answers it
 *   as it answers any rejection of the lookup.
 *
 * Boot installs the boundary in the `clientRepository` slot, over whatever
 * fills it, so every module that reads the slot reads through it. A record
 * is validated at each boundary it passes; a boundary this module built is
 * recognised and reused, never wrapped twice. A boundary over another lets
 * the inner one's refusal through unchanged, without a second warn.
 */

import type { z } from "zod";
import { auditErrorList, auditErrorText } from "../errors/envelope.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { EventLogger } from "../logging/Logger.mjs";
import type { ClientRepository, PublicClient } from "./ClientRepository.mjs";
import { ClientRecordRefusedError } from "./clientRecordRefused.mjs";
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
 * Proxy), and nothing else of it — never a `clientSecret` beside them. The
 * copy is parsed with its defaults filled, and the parse is copied once more,
 * so what is answered is frozen at every depth: a fresh object per lookup
 * that shares nothing with the record or with another answer. Its
 * `clientId` must be the id that was looked up, and an id no request could
 * name (`isWellFormedClientId`) is refused, as at boot.
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
	// The parse is a new, mutable object with the defaults filled: copied once
	// more by the same copier, so what is answered is frozen at every depth.
	// It holds only what the frozen copy held and the schema's defaults, so
	// the copy cannot fail.
	const answer = readPlainFields(parsed.data, CLIENT_RECORD_FIELDS);
	if (!answer.ok) return { ok: false, reasons: [`${answer.field}: not plain data`] };
	return { ok: true, client: answer.copy as PublicClient };
}

/** How many reasons a refusal's log line keeps. */
const LOGGED_REASONS_MAX = 10;

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
 * - A record that fails is refused: `findById` and `authenticate` reject
 *   with a new {@link ClientRecordRefusedError}. Each refusal writes one
 *   `client_record_refused` warn: the `step` (`find` or `authenticate`), the
 *   client id sanitised and capped, and the reasons, at most ten, each
 *   sanitised and capped (`reasonCount` when more). The record itself is
 *   never logged.
 * - `null` or `undefined` is no record: `null`, silently.
 * - A throw, the repository's or a field read's, is let through as it was
 *   thrown. So is an inner boundary's refusal, which stays a refusal and is
 *   not warned again; anything else is the store's outage.
 *
 * A layer over the boundary keeps a refusal as long as it lets rejections
 * through unchanged (see the file header). A boundary handed to it is
 * answered as it is, never wrapped twice, so it keeps the logger it was
 * first built with; `options` are not read. Building the boundary reads
 * nothing of `inner`. The boundary is always disposable: disposing it reads
 * `inner`'s `Symbol.asyncDispose` then, and calls it when it is a function.
 *
 * The reasons a refusal logs name the field and an entry's position, never a
 * URI (see the file header). The record object is never logged.
 */
export function validatedClientRepository(
	inner: ClientRepository,
	options: ClientRepositoryBoundaryOptions = {},
): ClientRepository {
	if (boundaries.has(inner)) return inner;
	const logger = options.logger ?? consoleLogger;
	const admit = (
		step: ClientRepositoryOutage["step"],
		clientId: string,
		record: PublicClient | null | undefined,
	): PublicClient | null => {
		if (record === null || record === undefined) return null;
		const reading =
			typeof record === "object"
				? readClientRecord(record, clientId)
				: ({ ok: false, reasons: ["not an object"] } as const);
		if (reading.ok) return reading.client;
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
		throw new ClientRecordRefusedError();
	};
	const boundary: ClientRepository & AsyncDisposable = {
		findById: async (clientId) => admit("find", clientId, await inner.findById(clientId)),
		authenticate: async (clientId, secret) =>
			admit("authenticate", clientId, await inner.authenticate(clientId, secret)),
		[Symbol.asyncDispose]: async () => {
			const dispose = (inner as { [Symbol.asyncDispose]?: unknown })[Symbol.asyncDispose];
			if (typeof dispose === "function") await dispose.call(inner);
		},
	};
	boundaries.add(boundary);
	return boundary;
}
