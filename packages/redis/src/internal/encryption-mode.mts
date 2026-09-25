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

import { consoleLogger, type Logger } from "@o3co/auth-provider-core";

/**
 * The production guard on storing upstream refresh tokens unencrypted
 * (OR-12 / #473), shared by the two stores that hold them: the session-bound
 * federation tokens (#293) and the federation grants of #593.
 *
 * One escape hatch, not two: `FEDERATION_TOKENS_ALLOW_INSECURE=1` is about
 * "IdP refresh tokens at rest without encryption", which is what both stores
 * would be doing. A second variable would let a deployment permit it for one
 * and be surprised by the other. The `label` is what the messages name, so
 * an operator is told which store refused.
 *
 * What it writes where plaintext goes ahead is one object-first line with an
 * event name — `federation_store_plaintext` (warn) where plaintext is
 * allowed, `federation_store_plaintext_override` (error) where only the
 * escape hatch let it through — on the logger the composition handed the
 * store, or `consoleLogger` when it handed none: a store is built by a
 * module or a builder that may have the composition's logger, or by a
 * caller that has none.
 */
const PRODUCTION_ENVS = new Set(["production", "staging"]);

/**
 * Where the guard looks beside the mode itself (#473). A deployment that has
 * declared more than one replica is never a development box, whatever its
 * environment is named.
 */
export interface EncryptionGuardContext {
	readonly environment?: string;
	readonly deploymentMode?: string;
	/**
	 * Where the guard's notice goes — the composition's logger, which a module
	 * reads from its optional `logger` slot and a builder from its context.
	 * Absent, `consoleLogger`.
	 */
	readonly logger?: Logger;
}

/**
 * OR-12 / #473 — refuse to construct a federation-token store with
 * `mode = "allow-plaintext"` where plaintext is not acceptable, unless the
 * operator explicitly sets `FEDERATION_TOKENS_ALLOW_INSECURE=1`. The refusal
 * is a `RangeError`, as every setting a store is given and cannot use is. Logs
 * `federation_store_plaintext_override` at error when the escape hatch is
 * active, naming what would have refused it. Everywhere else it logs
 * `federation_store_plaintext` at warn but does not throw.
 *
 * Plaintext is refused when any of these holds:
 *   - the explicit `environment` is `production` or `staging`;
 *   - `NODE_ENV` is `production` or `staging` (always consulted; the sole
 *     signal when no environment is passed);
 *   - `deploymentMode` is `"multi"`.
 */
export function validateEncryptionMode(
	label: string,
	mode: "required" | "allow-plaintext",
	{ environment, deploymentMode, logger = consoleLogger }: EncryptionGuardContext,
): void {
	if (mode === "required") return;
	const allowInsecure = process.env.FEDERATION_TOKENS_ALLOW_INSECURE === "1";

	// Both names are checked, and the one that matched is the one reported:
	// an operator whose CONFIG_ENV says production should not be told about
	// NODE_ENV, and vice versa.
	const productionEnvironment = [environment, process.env.NODE_ENV].find(
		(name): name is string => name !== undefined && PRODUCTION_ENVS.has(name),
	);
	const reasons: string[] = [];
	if (productionEnvironment !== undefined) {
		reasons.push(`the environment is "${productionEnvironment}"`);
	}
	if (deploymentMode === "multi") {
		reasons.push(
			'deployment.mode is "multi" (a multi-replica deployment is never a development box)',
		);
	}

	if (reasons.length > 0) {
		const because = reasons.join(" and ");
		if (allowInsecure) {
			// Upstream refresh tokens stored unencrypted where that is refused:
			// an error, on every boot, until the override is gone.
			logger.error(
				{
					store: label,
					mode,
					...(productionEnvironment !== undefined ? { environment: productionEnvironment } : {}),
					...(deploymentMode === "multi" ? { deploymentMode } : {}),
					override: "FEDERATION_TOKENS_ALLOW_INSECURE",
				},
				"federation_store_plaintext_override",
			);
			return;
		}
		throw new RangeError(
			`[${label}] mode "${mode}" is refused because ${because}. ` +
				'Set mode to "required" and provide a 32-byte encryption key, OR set ' +
				"FEDERATION_TOKENS_ALLOW_INSECURE=1 to override (NOT recommended for production).",
		);
	}

	// Dev/test: upstream refresh tokens stored unencrypted — allowed, and said.
	logger.warn({ store: label, mode }, "federation_store_plaintext");
}
