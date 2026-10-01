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
 * The variables renamed with a path of the composition root's own layers,
 * which no module declares: the adapter selections and the federations the
 * template ships. Phase one refuses an old name set alone, or beside its new
 * name at a different value, before any module is chosen; the two at one
 * value are accepted.
 */

/** A variable renamed with a path of the composition root's own: its old name, its new one, and the path the new one binds. */
export interface RootRename {
	readonly from: string;
	readonly to: string;
	readonly path: string;
}

/**
 * Refuses, with a `RangeError`, an old name in `env` set alone, or beside its
 * new name at a different value; the two at one value are accepted. Every
 * such rename is named at once; no value is quoted.
 */
export function refuseRenamedVariables(
	env: Readonly<Record<string, string>>,
	renames: readonly RootRename[],
): void {
	const refused = renames.flatMap(({ from, to, path }) => {
		const old = env[from];
		if (old === undefined || env[to] === old) return [];
		const renamed = `${from} was renamed ${to}, the variable ${path} is bound to; see CHANGELOG.`;
		return env[to] === undefined
			? [`${renamed} Set ${to} instead and unset ${from}.`]
			: [
					`${renamed} ${to} is set to a different value: keep the one you mean in ${to} and unset ${from}.`,
				];
	});
	if (refused.length > 0) {
		throw new RangeError(
			`The environment sets ${refused.length} variable(s) that were renamed: ${refused.join(" ")}`,
		);
	}
}

/**
 * The variables `config/application.conf` binds for the two federations the
 * template ships, each renamed after its path under `core.federations`.
 */
export const SHIPPED_FEDERATION_RENAMES: readonly RootRename[] = (
	[
		["GOOGLE", "google", ["ENABLED", "enabled"]],
		["GOOGLE", "google", ["CLIENT_ID", "clientId"]],
		["GOOGLE", "google", ["CLIENT_SECRET", "clientSecret"]],
		["GOOGLE", "google", ["CALLBACK_URL", "callbackURL"]],
		["GOOGLE", "google", ["ACCESS_TYPE", "accessType"]],
		["OIDC", "oidc", ["ENABLED", "enabled"]],
		["OIDC", "oidc", ["ISSUER", "issuer"]],
		["OIDC", "oidc", ["CLIENT_ID", "clientId"]],
		["OIDC", "oidc", ["CLIENT_SECRET", "clientSecret"]],
		["OIDC", "oidc", ["CALLBACK_URL", "callbackURL"]],
	] as const
).map(([federation, name, [key, path]]) => ({
	from: `FEDERATIONS_${federation}_${key}`,
	to: `CORE_FEDERATIONS_${federation}_${key}`,
	path: `core.federations.${name}.${path}`,
}));
