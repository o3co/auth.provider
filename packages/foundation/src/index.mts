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

import type { AdapterFactory, UserRepository } from "@o3co/auth-provider-core";
import {
	DEFAULT_MAX_RESPONSE_BYTES,
	HttpUserRepository,
} from "./repositories/HttpUserRepository.mjs";

/** Default request deadline, in milliseconds, when the config names none. */
const DEFAULT_TIMEOUT_MS = 5000;

/**
 * Coerces a numeric config value that may arrive as a string.
 *
 * HOCON environment substitution yields strings, so `CLIENT_USER_TIMEOUT=1234`
 * reaches the builder as `"1234"`. An *absent* key takes `fallback`; anything
 * present but unreadable becomes `NaN` and is rejected by the constructor,
 * which owns the range rules and names the field in its message.
 *
 * The distinction matters because HOCON substitutes a **blank** environment
 * variable as `""` — a very ordinary shape in a `.env` file or an empty
 * ConfigMap key — and `Number("")` is `0`. This used to fall back to the
 * default, hiding the misconfiguration; it is now a boot failure (#285).
 */
const toNumber = (value: unknown, fallback: number): number => {
	if (value === undefined || value === null) return fallback;
	if (typeof value === "number") return value;
	if (typeof value === "string") return Number(value.trim());
	return Number.NaN;
};

export const registerBuiltinAdapters = (factories: {
	userFactory: AdapterFactory<UserRepository>;
}): void => {
	factories.userFactory.register("http", (config) => {
		if (typeof config.authenticateUrl !== "string") {
			throw new Error('HttpUserRepository requires "authenticateUrl" in config');
		}
		if (typeof config.authenticateByTokenUrl !== "string") {
			throw new Error('HttpUserRepository requires "authenticateByTokenUrl" in config');
		}
		// Every remaining check — https-or-loopback, positive-integer timeout,
		// positive-integer cap — lives in the constructor, so a repository built
		// by hand is validated exactly as one built from config.
		return new HttpUserRepository({
			authenticateUrl: config.authenticateUrl,
			authenticateByTokenUrl: config.authenticateByTokenUrl,
			timeout: toNumber(config.timeout, DEFAULT_TIMEOUT_MS),
			maxResponseBytes: toNumber(config.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES),
		});
	});
};

export {
	DEFAULT_MAX_RESPONSE_BYTES,
	HttpUserRepository,
} from "./repositories/HttpUserRepository.mjs";
