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
 * The one reading of the federations a configuration declares: the map in
 * core's own section, `core.federations`, keyed by each federation's name.
 * Each entry is as written (core's schema coerces its switches), and read as
 * own properties: a key an object inherits is not one anyone wrote.
 */

/** The configuration's `core.federations` by name, own entries only; `{}` when it has none. */
export function federationsOf(config: unknown): Readonly<Record<string, unknown>> {
	const core = (config as { core?: unknown } | null | undefined)?.core;
	if (typeof core !== "object" || core === null || !Object.hasOwn(core, "federations")) return {};
	const federations = (core as { federations?: unknown }).federations;
	if (typeof federations !== "object" || federations === null || Array.isArray(federations)) {
		return {};
	}
	return Object.fromEntries(Object.entries(federations));
}
