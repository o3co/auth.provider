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
 * The `mtls` section as the package's `config/reference.conf` ships it, with
 * no variable set: the defaults a composition root layers under an
 * operator's settings. The schema holds none of its own, so a test that
 * writes a section lays its keys over this one.
 */

import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** `over` laid over `under` as one HOCON file over another: objects merged key by key, any other value replaced. */
function layered(under: unknown, over: unknown): unknown {
	if (!isPlainObject(under) || !isPlainObject(over)) return over;
	const merged: Record<string, unknown> = { ...under };
	for (const [key, value] of Object.entries(over)) merged[key] = layered(under[key], value);
	return merged;
}

/** The shipped `mtls` section, with `overrides` laid over it. */
export const shippedMtlsSection = (
	overrides: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> => {
	const tree = parseFile(fileURLToPath(REFERENCE), { env: {} }).toObject() as Record<
		string,
		unknown
	>;
	return layered(tree.mtls, overrides) as Record<string, unknown>;
};
