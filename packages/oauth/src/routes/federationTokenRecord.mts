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
 * The route's one hold on the stored record: it reads the record with its
 * store generation, writes only at the generation it read, and answers a
 * record that changed under a refresh. A logout, an unlink or a relink that
 * lands while a request is in flight is therefore never undone or
 * overwritten. A token held across the session's liveness read is handed on
 * only once the record is confirmed, after that read, at the generation it
 * was held from (`serveHeld`). No other stage calls the store's conditional
 * members or sees a generation. The route never removes a link from the
 * session's index: a link with no record is answered `404`, and the link ends
 * with the session.
 */

import {
	type FederationTokens,
	loggableError,
	readConditionalRemoveAnswer,
	readConditionalReplaceAnswer,
	readVersioned,
	type Versioned,
} from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
import { isUsableToken } from "./federationTokenCredential.mjs";
import { isDisclosable, refuseUndisclosableTokenType } from "./federationTokenDisclosure.mjs";
import { refreshIsDue } from "./federationTokenRefreshDue.mjs";
import { checkSessionLive } from "./federationTokenSession.mjs";
import { answerToken } from "./federationTokenSuccess.mjs";
import { answerUnlinkedRecord } from "./federationTokenUnlinked.mjs";

/** The record as one read found it; a write against it lands only if nothing wrote the record since. */
export type StoredRecord = Versioned<FederationTokens>;

/**
 * Reads the record. Returns it, or `null` once answered: `404` when there is
 * none, `503` when the store cannot answer or answers outside its contract.
 */
export const readRecord = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	step: "get" | "get_after_lock" | "get_after_conflict",
): Promise<StoredRecord | null> => {
	const read = await readStored(ctx, caller, step);
	if (read === null) answerUnlinkedRecord(ctx);
	return read ?? null;
};

/**
 * Confirms the record is still as `read` found it, before a token held from
 * `read` is handed on with no write that confirmed it. Returns `null` when it
 * is; otherwise answers as a dropped refresh is answered, or `503` when the
 * store cannot answer, and returns that response.
 */
export const answerIfChanged = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	read: StoredRecord,
): Promise<Response | null> => {
	const found = await confirmHeld(ctx, caller, read);
	if (found === "answered") return ctx.res;
	if (found === "held") return null;
	return answerDiscardedRefresh(ctx, caller, found);
};

/**
 * Hands on what `serve` answers from `held` once the caller's session is live
 * and, read after that, the record is still at `held`'s generation. A record
 * gone meanwhile is answered as removed (`404`), one rewritten as a conflict.
 */
export const serveHeld = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	held: StoredRecord,
	serve: () => Promise<Response>,
): Promise<Response> => {
	if (!(await checkSessionLive(ctx, caller))) return ctx.res;
	const changed = await answerIfChanged(ctx, caller, held);
	return changed ?? serve();
};

/**
 * Whether the record is still at `held`'s generation: `held`, `missing`,
 * `conflict`, or `answered` once a store that cannot answer is answered `503`.
 */
const confirmHeld = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	held: StoredRecord,
): Promise<"held" | "missing" | "conflict" | "answered"> => {
	const found = await readStored(ctx, caller, "get_before_serve");
	if (found === undefined) return "answered";
	if (found === null) return "missing";
	return found.generation === held.generation ? "held" : "conflict";
};

/**
 * The versioned read: the record, `null` when there is none, or `undefined`
 * once a store that cannot answer, or answers outside its contract, is
 * answered `503`.
 */
const readStored = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	step: "get" | "get_after_lock" | "get_after_conflict" | "get_before_serve",
): Promise<StoredRecord | null | undefined> => {
	const { opts, res, federation, storeUnavailable } = ctx;
	try {
		return readVersioned(await opts.federationTokenStore.getVersioned(caller.sid, ctx.name));
	} catch (error) {
		storeUnavailable(federation, "federation_token", step, error);
		res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "federation token store unavailable",
		});
		return undefined;
	}
};

/**
 * Hands on the stored token of a record that is not due for refresh. A
 * record with no usable access token is removed as it was read, best effort,
 * and answered as none; its usability is judged only here, where a token
 * would be handed on, so a due one is still refreshed from its refresh token.
 */
export const serveStored = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	read: StoredRecord,
): Promise<Response> => {
	const { federation, logger } = ctx;
	const tokens = read.value;
	if (!isUsableToken(tokens.accessToken)) {
		let removal: Awaited<ReturnType<typeof removeRecord>> | "failed";
		try {
			removal = await removeRecord(ctx, caller, read);
		} catch (error) {
			removal = "failed";
			logger.warn(
				{ federation, store: "federation_token", step: "remove_if", err: loggableError(error) },
				"federation_token_cleanup_failed",
			);
		}
		// The federation and what the removal found, never what the record holds.
		logger.warn({ federation, removal }, "federation_token_record_unusable");
		return answerUnlinkedRecord(ctx);
	}
	// The type is judged before the token is read and before the success is
	// audited, so a refused disclosure is not counted as one.
	if (!isDisclosable(tokens)) {
		return refuseUndisclosableTokenType(ctx, caller, tokens.tokenType);
	}
	return answerToken(ctx, caller, tokens, false);
};

/**
 * Replaces the record only while it is still as `read` found it: `updated`
 * with the record as written. Rejects when the store cannot answer or answers
 * outside its contract: the write's fate is then unknown.
 */
export const replaceRecord = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	read: StoredRecord,
	next: FederationTokens,
): Promise<
	| { readonly outcome: "updated"; readonly written: StoredRecord }
	| { readonly outcome: "missing" | "conflict" }
> => {
	const answer = readConditionalReplaceAnswer(
		await ctx.opts.federationTokenStore.replaceIf(caller.sid, ctx.name, read.generation, next),
	);
	if (answer.outcome !== "updated") return { outcome: answer.outcome };
	return { outcome: "updated", written: { value: next, generation: answer.generation } };
};

/** Removes the record only while it is still as `read` found it. Rejects as `replaceRecord` does. */
export const removeRecord = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	read: StoredRecord,
): Promise<"removed" | "missing" | "conflict"> => {
	const answer = await ctx.opts.federationTokenStore.removeIf(
		caller.sid,
		ctx.name,
		read.generation,
	);
	return readConditionalRemoveAnswer(answer).outcome;
};

/**
 * The answer once a refresh's own result is dropped because the record is no
 * longer the one it was made from. `missing`: the user removed the link, so
 * nothing of it is handed on (`404`). `conflict`: the record was rewritten
 * (a relink, or another refresh), so the current record is answered as
 * stored if it is not due, the session is still live and, read after that,
 * the record is still the one read (`404` if it is gone by then); and `503`
 * if it is due or was rewritten again: the refresh is never repeated within
 * one request, and the client's retry refreshes it.
 */
export const answerDiscardedRefresh = async (
	ctx: FederationTokenContext,
	caller: FederationTokenCaller,
	outcome: "missing" | "conflict",
): Promise<Response> => {
	const { res, federation, logger } = ctx;
	logger.warn(
		{
			federation,
			store: "federation_token",
			reason: outcome === "missing" ? "record_gone" : "record_replaced",
		},
		"federation_token_refresh_discarded",
	);
	if (outcome === "missing") return answerUnlinkedRecord(ctx);
	const current = await readRecord(ctx, caller, "get_after_conflict");
	if (current === null) return res;
	if (!refreshIsDue(ctx, current.value)) {
		// After the upstream call: served only while the session is still live.
		if (!(await checkSessionLive(ctx, caller))) return res;
		const found = await confirmHeld(ctx, caller, current);
		if (found === "answered") return res;
		if (found === "held") return serveStored(ctx, caller, current);
		if (found === "missing") return answerDiscardedRefresh(ctx, caller, "missing");
	}
	return res.status(503).json({
		error: "temporarily_unavailable",
		error_description: "the federation token was replaced concurrently; retry",
	});
};
