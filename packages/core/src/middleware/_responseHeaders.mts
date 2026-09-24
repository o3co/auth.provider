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

import type { Response } from "express";

/**
 * The response headers a token-binding outcome asks for (#530): a refusal
 * (an error carrying `responseHeaders`) or an accepted binding
 * (`TokenBinding.responseHeaders`). Only string-valued entries count — a
 * mechanism cannot smuggle a non-header through.
 */
export const responseHeadersOf = (source: unknown): Readonly<Record<string, string>> => {
	if (typeof source !== "object" || source === null || !("responseHeaders" in source)) return {};
	const headers = (source as { responseHeaders?: unknown }).responseHeaders;
	if (typeof headers !== "object" || headers === null) return {};
	return Object.fromEntries(
		Object.entries(headers as Record<string, unknown>).filter(
			(entry): entry is [string, string] => typeof entry[1] === "string",
		),
	);
};

/** Set every header {@link responseHeadersOf} finds on `source`. */
export const applyResponseHeaders = (res: Response, source: unknown): void => {
	for (const [name, value] of Object.entries(responseHeadersOf(source))) {
		res.setHeader(name, value);
	}
};

/** An OAuth error code: snake_case, so an infrastructure code (`ECONNREFUSED`) never reaches the wire. */
const OAUTH_ERROR_CODE_PATTERN = /^[a-z][a-z0-9_]*$/;

/** The OAuth error `code` a thrown refusal carries, or `undefined`. */
export const oauthErrorCodeOf = (err: unknown): string | undefined => {
	const code =
		typeof err === "object" && err !== null ? (err as { code?: unknown }).code : undefined;
	return typeof code === "string" && OAUTH_ERROR_CODE_PATTERN.test(code) ? code : undefined;
};

/**
 * The retry instruction a refusal states (`TokenBindingRefusal.retryInstruction`),
 * or `undefined` for a verdict. Only a non-empty string beside an OAuth code
 * counts: an instruction with no code to answer under is not one.
 */
export const retryInstructionOf = (err: unknown): string | undefined => {
	if (oauthErrorCodeOf(err) === undefined) return undefined;
	const instruction = (err as { retryInstruction?: unknown }).retryInstruction;
	return typeof instruction === "string" && instruction.length > 0 ? instruction : undefined;
};

/**
 * The outage a refusal reports (`TokenBindingRefusal.unavailable`), or
 * `undefined` when it is not one. Same rule as {@link retryInstructionOf}: a
 * non-empty string beside an OAuth code, so a mechanism has to say both what
 * to answer and that it is the server's fault.
 */
export const unavailableOf = (err: unknown): string | undefined => {
	if (oauthErrorCodeOf(err) === undefined) return undefined;
	const description = (err as { unavailable?: unknown }).unavailable;
	return typeof description === "string" && description.length > 0 ? description : undefined;
};
