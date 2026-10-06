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
 * Where core's CORS origins come from: the CORS origins of a held
 * `httpSettings` slot, checked — what core's CORS middleware reads when the
 * slot's key is present, whatever a provider answered; core reads nothing
 * else of it — and the refusal of a configuration's `cors` section, which
 * core never reads.
 */

import { pathsSetBy, unreadSectionMessage } from "../config/removed-keys.mjs";
import { describeValue } from "../errors/describe-value.mjs";
import { checkSerializedOrigin, describeSerializedOriginRejection } from "../net/origin.mjs";

const UNREAD_CORS = unreadSectionMessage(
	"cors",
	"The CORS origins are handed to core in the httpSettings slot (cors.allowedOrigins), by the module that provides the slot: write them where that module reads them. Without the slot, no CORS is mounted.",
);

/**
 * Why `config`'s top-level `cors` section refuses boot, or `undefined` when
 * a loaded module's section is `cors` (`owned`, the top-level sections
 * something loaded owns), which reads it, or when it sets nothing: absent,
 * an own `undefined` (as the relocation refusal reads it), or a value
 * `pathsSetBy` finds nothing in (`{}`, or only empty sections). Core reads
 * its CORS origins from the `httpSettings` slot alone, so any other `cors`
 * is read by nothing; a loaded module that relocates `cors` refuses it
 * first, before parse, naming its own path. A section whose read throws
 * refuses the same way. Names the section, never a value.
 */
export function unreadCorsSection(config: unknown, owned: ReadonlySet<string>): string | undefined {
	if (owned.has("cors")) return undefined;
	if (typeof config !== "object" || config === null || !Object.hasOwn(config, "cors")) {
		return undefined;
	}
	try {
		const cors: unknown = (config as Record<string, unknown>).cors;
		return cors !== undefined && pathsSetBy(cors).length > 0 ? UNREAD_CORS : undefined;
	} catch {
		return UNREAD_CORS;
	}
}

const WHY =
	"Core's CORS middleware reads its origins from the httpSettings a composition holds, so a " +
	"slot that breaks its contract is refused rather than read.";

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
 * `checkSerializedOrigin` (the rule the module's schema holds its section's to),
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
