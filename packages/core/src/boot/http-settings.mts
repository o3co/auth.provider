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
 * The CORS origins of a held `httpSettings` slot, checked: what core's CORS
 * middleware reads instead of `cors.allowedOrigins` when the slot's key is
 * present, whatever a provider answered. Core reads nothing else of it.
 */

import { describeValue } from "../errors/describe-value.mjs";
import { checkSerializedOrigin, describeSerializedOriginRejection } from "../net/origin.mjs";

const WHY =
	"Core's CORS middleware reads its origins from the httpSettings a composition holds, and " +
	"from the configuration only when it holds none, so a slot that breaks its contract is " +
	"refused rather than read beside the configuration's.";

const refuse = (member: string, rule: string): never => {
	throw new RangeError(`httpSettings.${member} ${rule}. ${WHY}`);
};

/** A member of a host's value, read once; a read that throws is refused, naming the member. */
const readOnce = (member: string, read: () => unknown): unknown => {
	try {
		return read();
	} catch (err) {
		throw new RangeError(`httpSettings.${member} could not be read: reading it threw. ${WHY}`, {
			cause: err,
		});
	}
};

/**
 * The slot's `cors.allowedOrigins`, read once, each entry held to
 * `checkSerializedOrigin` (the rule the schema holds the configuration's to),
 * answered as a frozen copy.
 *
 * @throws RangeError naming the member (and the index) that does not hold,
 *   or the slot when it holds no settings object.
 */
export function httpSettingsCorsOrigins(value: unknown): readonly string[] {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new RangeError(
			`httpSettings must be the settings object its contract describes, and the composition's slot holds ${describeValue(value)}. ${WHY}`,
		);
	}
	const cors = readOnce("cors", () => (value as Record<string, unknown>).cors);
	const list =
		typeof cors === "object" && cors !== null
			? readOnce("cors.allowedOrigins", () => (cors as Record<string, unknown>).allowedOrigins)
			: undefined;
	if (!Array.isArray(list)) {
		return refuse(
			"cors.allowedOrigins",
			`must be a list of serialized origins, and the composition's slot carries ${list === undefined ? "none" : describeValue(list)}`,
		);
	}
	const origins = readOnce("cors.allowedOrigins", () => [...list]) as unknown[];
	origins.forEach((origin, index) => {
		if (typeof origin !== "string") {
			refuse(`cors.allowedOrigins[${index}]`, `is not a string: ${describeValue(origin)}`);
			return;
		}
		const rejection = checkSerializedOrigin(origin);
		if (rejection !== null) {
			refuse(`cors.allowedOrigins[${index}]`, describeSerializedOriginRejection(rejection));
		}
	});
	return Object.freeze(origins as string[]);
}
