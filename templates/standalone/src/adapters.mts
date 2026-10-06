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
 * The composition root's own section, `adapters`: which adapter fills each
 * slot. Phase one reads it alone, before the modules are chosen, with the
 * template's own schema; boot is never handed it. The paths the selections
 * moved from, and the variables renamed with them, are refused here, before
 * any module is chosen, in the words and under the reasons boot refuses a
 * module's with (`config-path-relocated`, `environment-variable-renamed`): a
 * renamed variable set alone, or beside its new name at a different value, is
 * refused, naming the variables and never a value.
 */

import { configRefused, issuesAt, pathsRelocated } from "./bootRefusal.mjs";
import { refuseRenamedVariables } from "./rootRenames.mjs";
import { type Adapters, adaptersSchema } from "./sections.mjs";

/** The composition root's own section. No module may be named after it. */
export const ADAPTERS_SECTION = "adapters";

/** Each selection's key under `adapters`, and the variable its path is bound to. */
const VARIABLES: Readonly<Record<keyof Adapters, string>> = {
	rateLimiter: "ADAPTERS_RATE_LIMITER",
	attemptCounter: "ADAPTERS_ATTEMPT_COUNTER",
	userSessionStores: "ADAPTERS_USER_SESSION_STORES",
	accessTokenDenylist: "ADAPTERS_ACCESS_TOKEN_DENYLIST",
	replaySeenSet: "ADAPTERS_REPLAY_SEEN_SET",
	consentStore: "ADAPTERS_CONSENT_STORE",
	federationTokenStore: "ADAPTERS_FEDERATION_TOKEN_STORE",
	federationGrantStore: "ADAPTERS_FEDERATION_GRANT_STORE",
	federationGrantIntentStore: "ADAPTERS_FEDERATION_GRANT_INTENT_STORE",
	mfaFactorStore: "ADAPTERS_MFA_FACTOR_STORE",
	mfaTransactionStore: "ADAPTERS_MFA_TRANSACTION_STORE",
	codeRepository: "ADAPTERS_CODE_REPOSITORY",
	clientRepository: "ADAPTERS_CLIENT_REPOSITORY",
	userRepository: "ADAPTERS_USER_REPOSITORY",
	auditSink: "ADAPTERS_AUDIT_SINK",
};

/** Each selection's old path, and its key under `adapters`. */
const MOVED: readonly (readonly [string, keyof Adapters])[] = [
	["rateLimiter.adapter", "rateLimiter"],
	["userSessionStores.adapter", "userSessionStores"],
	["accessTokenDenylist.adapter", "accessTokenDenylist"],
	["replaySeenSet.adapter", "replaySeenSet"],
	["consentStore.adapter", "consentStore"],
	["federationTokenStore.type", "federationTokenStore"],
	["federationGrantStore.adapter", "federationGrantStore"],
	["federationGrantIntentStore.adapter", "federationGrantIntentStore"],
	["mfaFactorStore.adapter", "mfaFactorStore"],
	["mfaTransactionStore.adapter", "mfaTransactionStore"],
	["oauth.code.adapter", "codeRepository"],
	["repositories.code.type", "codeRepository"],
	["repositories.client.type", "clientRepository"],
	["repositories.user.type", "userRepository"],
	["audit.sink.type", "auditSink"],
];

/** Each variable renamed with a selection, and the selection's key under `adapters`. */
const RENAMED: readonly (readonly [string, keyof Adapters])[] = [
	["RATE_LIMITER_ADAPTER", "rateLimiter"],
	["USER_SESSION_STORES_ADAPTER", "userSessionStores"],
	["ACCESS_TOKEN_DENYLIST_ADAPTER", "accessTokenDenylist"],
	["REPLAY_SEEN_SET_ADAPTER", "replaySeenSet"],
	["CONSENT_STORE_ADAPTER", "consentStore"],
	["FEDERATION_TOKEN_STORE_TYPE", "federationTokenStore"],
	["FEDERATION_GRANT_STORE_ADAPTER", "federationGrantStore"],
	["FEDERATION_GRANT_INTENT_STORE_ADAPTER", "federationGrantIntentStore"],
	["MFA_FACTOR_STORE_ADAPTER", "mfaFactorStore"],
	["MFA_TRANSACTION_STORE_ADAPTER", "mfaTransactionStore"],
	["OAUTH_CODE_ADAPTER", "codeRepository"],
	["CLIENT_CODE_TYPE", "codeRepository"],
	["CLIENT_TYPE", "clientRepository"],
	["CLIENT_USER_TYPE", "userRepository"],
	["AUDIT_SINK_TYPE", "auditSink"],
];

/** The value at a dotted `path` of `config`, read as own properties; `undefined` when absent. */
function valueAt(config: unknown, path: string): unknown {
	let cursor: unknown = config;
	for (const key of path.split(".")) {
		if (typeof cursor !== "object" || cursor === null || !Object.hasOwn(cursor, key)) {
			return undefined;
		}
		cursor = (cursor as Record<string, unknown>)[key];
	}
	return cursor;
}

/**
 * `adapters` from `resolved` — the template's own layers over its
 * `config/reference.conf` — under `env`, the environment they were
 * substituted with, parsed with the template's schema. Refuses, each with a
 * `BootError` (`bootRefusal.mts`), a selection still written at the path it
 * moved from, naming its new path and variable (`config-path-relocated`);
 * then a variable renamed with one (`refuseRenamedVariables`); then a value
 * or a key the schema refuses, naming its path under `adapters`
 * (`config-validation-failed`).
 */
export function readAdapters(
	resolved: Readonly<Record<string, unknown>>,
	env: Readonly<Record<string, string>>,
): Adapters {
	const moved = MOVED.filter(([from]) => valueAt(resolved, from) !== undefined).map(
		([from, key]) => ({
			module: ADAPTERS_SECTION,
			from,
			to: `${ADAPTERS_SECTION}.${key}`,
			environmentVariable: VARIABLES[key],
		}),
	);
	if (moved.length > 0) {
		throw pathsRelocated(
			`Configuration sets ${moved.length} path(s) that moved: ${moved
				.map(
					({ from, to, environmentVariable }) =>
						`${from} has moved to ${to}; see CHANGELOG. Write it there (environment variable ${environmentVariable}) and remove this field from your config (or unset the environment variable that sets it).`,
				)
				.join(" ")}`,
			moved,
		);
	}
	refuseRenamedVariables(
		env,
		RENAMED.map(([from, key]) => ({
			module: ADAPTERS_SECTION,
			from,
			to: VARIABLES[key],
			path: `${ADAPTERS_SECTION}.${key}`,
		})),
	);
	const result = adaptersSchema.safeParse(resolved[ADAPTERS_SECTION]);
	if (!result.success) {
		const issues = issuesAt([ADAPTERS_SECTION], result.error.issues);
		throw configRefused(
			`Config validation failed — ${issues.length} issue(s) found: ${issues
				.map((issue) => {
					const unknown =
						issue.code === "unrecognized_keys" ? ` ${JSON.stringify(issue.keys)}` : "";
					return `${issue.path.map(String).join(".")}: ${issue.message}${unknown}`;
				})
				.join("; ")}`,
			issues,
			[{ module: ADAPTERS_SECTION, schemaPath: ADAPTERS_SECTION }],
		);
	}
	return result.data;
}
