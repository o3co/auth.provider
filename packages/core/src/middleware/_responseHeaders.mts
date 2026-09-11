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

/** Whether `err` carries the OAuth error `code`. */
export const hasErrorCode = (err: unknown, code: string): boolean =>
	typeof err === "object" && err !== null && (err as { code?: unknown }).code === code;
