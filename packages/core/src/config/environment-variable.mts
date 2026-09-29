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
 * The environment variable a configuration path is bound to: the section
 * name and its keys in upper snake case, joined with `_`
 * (`device-grant.codeLifetimeSeconds` is `DEVICE_GRANT_CODE_LIFETIME_SECONDS`;
 * a list index is a key of its own, `mfa.encryptionKeys.0.key` is
 * `MFA_ENCRYPTION_KEYS_0_KEY`). Hyphens become `_`; a camelCase key splits
 * before each capital following a lower-case letter or a digit, and before
 * the last capital of a run followed by a lower-case letter (`jwksURLPath` is
 * `JWKS_URL_PATH`). The rule decides the name; whether a package's
 * `reference.conf` binds it is that package's.
 */

/** One key of a path in upper snake case. */
const upperSnake = (key: string): string =>
	key
		.replace(/([a-z0-9])([A-Z])/g, "$1_$2")
		.replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
		.replace(/-/g, "_")
		.toUpperCase();

/** The environment variable bound to the path whose keys are `path`, in order. */
export function environmentVariableFor(path: readonly string[]): string {
	return path.map(upperSnake).join("_");
}
