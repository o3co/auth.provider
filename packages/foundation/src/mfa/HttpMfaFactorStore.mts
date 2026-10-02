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
 * `MfaFactorStore` kept by the Store, over its four MFA factor endpoints
 * (README, "The Store's MFA endpoints"), on the user repository's transport.
 *
 * Guarantees: every answer the contract does not give an operation throws —
 * a list is never answered as fewer records, an update never as written; a
 * list is read whole or refused (a record the provider cannot read, one of
 * another subject, an id twice); an update's answer must be the record named,
 * with the changes sent, at the expected version plus one; what is thrown is
 * built from an allowlist (`storeFailure.mts`, `storeErrors.mts`) and carries
 * nothing the Store sent; the sealed `data` it is handed is sent as it is,
 * and nothing is sent that the wire codec would not read back.
 *
 * The factor set's members (`listVersioned`, `createIf`, `removeIf`) read
 * every answer through core's codec alone, once: a status the operation does
 * not give is `unexpected_status`, read before any body, and whatever the
 * codec refuses — a `404` or `409` without its outcome body among them — is
 * `malformed_answer`. A conditional write that is sent and then fails, its
 * deadline included, is unknown: it may have committed.
 */

import {
	type ConditionalCreateAnswer,
	type ConditionalSetRemoveAnswer,
	fromMfaStoreFactor,
	type MfaFactorRecord,
	type MfaFactorRecordUpdate,
	type MfaFactorStore,
	type MfaStoreCreateRequest,
	type MfaStoreDeleteRequest,
	type MfaStoreFactor,
	type MfaStoreFactorChanges,
	type MfaStoreListRequest,
	readMfaStoreCreateIfAnswer,
	readMfaStoreFactor,
	readMfaStoreListAnswer,
	readMfaStoreRemoveIfAnswer,
	readMfaStoreVersionedListAnswer,
	type StoreGeneration,
	toMfaStoreCreateIfRequest,
	toMfaStoreFactor,
	toMfaStoreRemoveIfRequest,
	toMfaStoreUpdateRequest,
	type VersionedSet,
} from "@o3co/auth-provider-core";
import { assertSecureEndpoint } from "../endpointUrl.mjs";
import {
	bearerAuthorization,
	checkStoreResponseCap,
	checkStoreTimeout,
	DEFAULT_MAX_RESPONSE_BYTES,
	postToStore,
	type StoreAnswer,
	type StoreRequestSettings,
} from "../storeTransport.mjs";
import {
	type MfaStoreOperation,
	mfaStoreMalformedAnswer,
	mfaStoreRequestMessages,
	mfaStoreStatusError,
	mfaStoreUnreadableRecord,
	mfaStoreVersionSkipped,
} from "./storeFailure.mjs";

/** What this adapter's messages lead with. */
const OWNER = "HttpMfaFactorStore";

/** The port's refusal of a `(subject, id)` already held, as the bundled stores word it. */
const DUPLICATE = "an MFA factor record with this id already exists for the subject";

/** The statuses a conditional create is answered with, each with its outcome body. */
const CREATE_IF_STATUSES: ReadonlySet<number> = new Set([200, 409]);

/** The statuses a conditional removal is answered with, each with its outcome body. */
const REMOVE_IF_STATUSES: ReadonlySet<number> = new Set([200, 404, 409]);

export interface HttpMfaFactorStoreOptions {
	/** The Store's four MFA factor endpoints, each https or loopback http. */
	readonly listUrl: string;
	readonly createUrl: string;
	readonly updateUrl: string;
	readonly deleteUrl: string;
	/** The user repository's credential: sent as `Authorization: Bearer <token>`. */
	readonly bearerToken?: string;
	/** The whole exchange's deadline, in milliseconds. */
	readonly timeout: number;
	/** The most bytes of an answer read. Default `DEFAULT_MAX_RESPONSE_BYTES`. */
	readonly maxResponseBytes?: number;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** What JSON text parses to, or `NOT_JSON`. */
const NOT_JSON: unique symbol = Symbol("not JSON");
function parsed(text: string): unknown {
	try {
		return JSON.parse(text);
	} catch {
		return NOT_JSON;
	}
}

/** Whether `factor` holds exactly the changes an update sent. */
const wrote = (factor: MfaStoreFactor, changes: MfaStoreFactorChanges): boolean =>
	factor.data === changes.data &&
	factor.label === changes.label &&
	factor.lastUsedAtMs === changes.lastUsedAtMs;

export class HttpMfaFactorStore implements MfaFactorStore {
	readonly kind = "store";
	/** Private fields: `inspect()` and `JSON.stringify` of the store show neither the credential nor the endpoints. */
	readonly #urls: Readonly<Record<"list" | "create" | "update" | "delete", string>>;
	readonly #settings: StoreRequestSettings;

	constructor({
		listUrl,
		createUrl,
		updateUrl,
		deleteUrl,
		bearerToken,
		timeout,
		maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
	}: HttpMfaFactorStoreOptions) {
		this.#urls = Object.freeze({
			list: assertSecureEndpoint(listUrl, "listUrl", OWNER),
			create: assertSecureEndpoint(createUrl, "createUrl", OWNER),
			update: assertSecureEndpoint(updateUrl, "updateUrl", OWNER),
			delete: assertSecureEndpoint(deleteUrl, "deleteUrl", OWNER),
		});
		this.#settings = Object.freeze({
			authorization: bearerAuthorization(bearerToken, OWNER),
			timeout: checkStoreTimeout(timeout, OWNER),
			maxResponseBytes: checkStoreResponseCap(maxResponseBytes, OWNER),
		});
	}

	async list(subject: string): Promise<readonly MfaFactorRecord[]> {
		const url = this.#urls.list;
		const body: MfaStoreListRequest = { subject };
		const { response, text } = await this.#post("list", body, (status) => status === 200);
		if (text === undefined) throw mfaStoreStatusError("list", url, response);
		const reading = readMfaStoreListAnswer(parsed(text), subject);
		if (!reading.ok) {
			throw reading.reason === "malformed"
				? mfaStoreMalformedAnswer("list", url)
				: mfaStoreUnreadableRecord(url);
		}
		return reading.factors.map(fromMfaStoreFactor);
	}

	async listVersioned(subject: string): Promise<VersionedSet<MfaFactorRecord>> {
		const body: MfaStoreListRequest = { subject };
		const { response, text } = await this.#post("list", body, (status) => status === 200);
		if (text === undefined) throw mfaStoreStatusError("list", this.#urls.list, response);
		return this.#read("list", () => readMfaStoreVersionedListAnswer(parsed(text), subject));
	}

	async createIf(
		record: MfaFactorRecord,
		expected: StoreGeneration | null,
	): Promise<ConditionalCreateAnswer> {
		const body = toMfaStoreCreateIfRequest(record, expected);
		const { response, text } = await this.#post("create", body, (status) =>
			CREATE_IF_STATUSES.has(status),
		);
		if (text === undefined) throw mfaStoreStatusError("create", this.#urls.create, response);
		return this.#read("create", () => readMfaStoreCreateIfAnswer(response.status, parsed(text)));
	}

	async removeIf(
		subject: string,
		id: string,
		expected: StoreGeneration,
	): Promise<ConditionalSetRemoveAnswer> {
		const body = toMfaStoreRemoveIfRequest(subject, id, expected);
		const { response, text } = await this.#post("delete", body, (status) =>
			REMOVE_IF_STATUSES.has(status),
		);
		if (text === undefined) throw mfaStoreStatusError("delete", this.#urls.delete, response);
		return this.#read("delete", () => readMfaStoreRemoveIfAnswer(response.status, parsed(text)));
	}

	async create(record: MfaFactorRecord): Promise<void> {
		const body: MfaStoreCreateRequest = { factor: toMfaStoreFactor(record) };
		const { response } = await this.#post("create", body, () => false);
		if (response.ok) return;
		if (response.status === 409) throw new Error(DUPLICATE);
		throw mfaStoreStatusError("create", this.#urls.create, response);
	}

	async update(
		subject: string,
		id: string,
		expectedVersion: number,
		next: MfaFactorRecordUpdate,
	): Promise<MfaFactorRecord | null> {
		const url = this.#urls.update;
		const body = toMfaStoreUpdateRequest(subject, id, expectedVersion, next);
		const { response, text } = await this.#post("update", body, (status) => status === 200);
		if (response.status === 409 || response.status === 404) return null;
		if (text === undefined) throw mfaStoreStatusError("update", url, response);
		const answer = parsed(text);
		const factor =
			isRecord(answer) && Object.hasOwn(answer, "factor")
				? readMfaStoreFactor(answer.factor)
				: undefined;
		if (
			factor === undefined ||
			factor.subject !== subject ||
			factor.id !== id ||
			!wrote(factor, body.changes)
		) {
			throw mfaStoreMalformedAnswer("update", url);
		}
		if (factor.version !== expectedVersion + 1) {
			throw mfaStoreVersionSkipped(url, { subject, id, expectedVersion });
		}
		return fromMfaStoreFactor(factor);
	}

	async remove(subject: string, id: string): Promise<void> {
		await this.#delete({ subject, id });
	}

	async removeAllForSubject(subject: string): Promise<void> {
		await this.#delete({ subject, all: true });
	}

	/** A delete: done on a `2xx` or a `404`. */
	async #delete(body: MfaStoreDeleteRequest): Promise<void> {
		const { response } = await this.#post("delete", body, () => false);
		if (response.ok || response.status === 404) return;
		throw mfaStoreStatusError("delete", this.#urls.delete, response);
	}

	/**
	 * What `read`, a reader of core's codec, makes of an answer of
	 * `operation`; the `TypeError` it throws for an answer outside the
	 * contract is `malformed_answer`, carrying none of the reader's words.
	 */
	#read<A>(operation: "list" | "create" | "delete", read: () => A): A {
		try {
			return read();
		} catch (error) {
			if (error instanceof TypeError) {
				throw mfaStoreMalformedAnswer(operation, this.#urls[operation]);
			}
			throw error;
		}
	}

	/** `body` to `operation`'s endpoint, its answer read when `readsBody` says so. */
	#post(
		operation: Exclude<MfaStoreOperation, "markMfaEnrolled">,
		body: unknown,
		readsBody: (status: number) => boolean,
	): Promise<StoreAnswer> {
		const url = this.#urls[operation];
		return postToStore(
			url,
			body,
			this.#settings,
			mfaStoreRequestMessages(OWNER, operation, url),
			readsBody,
		);
	}
}
