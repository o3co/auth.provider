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
 * Which federation a callback request is for, and what it carries: an
 * installed provider reached by the one method its response mode uses (the
 * other is `405`, refused before any cookie is read), and its parameters
 * narrowed to string entries.
 */

import {
	errorEnvelope,
	type FederationProvider,
	resolveFederationResponseMode,
	sanitizeErrorText,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import type { FederationRouterContext } from "./FederationContext.mjs";

/**
 * Narrow a callback's parameter bag (`req.query` or `req.body`) to its string
 * entries. Both are attacker-shapeable (repeats arrive as arrays, bodies can
 * nest), so `state` is only ever compared with a string or `undefined`, and
 * adapters get flat strings.
 */
export const readCallbackParams = (source: unknown): Readonly<Record<string, string>> => {
	if (source == null || typeof source !== "object") return {};
	return Object.fromEntries(
		Object.entries(source as Record<string, unknown>).filter(
			(entry): entry is [string, string] => typeof entry[1] === "string",
		),
	);
};

/**
 * The installed provider a callback names, reached by its response mode's
 * method: `query` by `GET`, `form_post` by `POST`. Answers `404` or `405` and
 * returns `null` otherwise.
 */
export const resolveCallbackProvider = (
	ctx: FederationRouterContext,
	source: "query" | "body",
	req: Request,
	res: Response,
): FederationProvider | null => {
	const { federationProviders } = ctx;
	const provider = federationProviders.get(String(req.params.name));
	if (!provider) {
		res
			.status(404)
			.json(
				errorEnvelope(
					"not_found",
					`Federation provider not registered: ${String(req.params.name)}`,
				),
			);
		return null;
	}

	const providerResponseMode = resolveFederationResponseMode(provider);

	if (source === "body" && providerResponseMode !== "form_post") {
		res
			.status(405)
			.set("Allow", "GET")
			.json({
				error: "method_not_allowed",
				error_description: sanitizeErrorText(
					`Federation '${provider.name}' returns its authorization response in the query string; the POST callback is accepted only for a form_post federation`,
				),
			});
		return null;
	}

	// A form_post IdP only POSTs here; a GET is a misconfiguration or a
	// probe carrying the victim's `SameSite=None` transaction cookie.
	// Refused before the cookie is read, so a third party's `<img>` never
	// reaches the transaction.
	if (source === "query" && providerResponseMode === "form_post") {
		res
			.status(405)
			.set("Allow", "POST")
			.json({
				error: "method_not_allowed",
				error_description: sanitizeErrorText(
					`Federation '${provider.name}' returns its authorization response as a form post; the GET callback is accepted only for a query federation`,
				),
			});
		return null;
	}

	return provider;
};
