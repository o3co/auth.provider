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
 * The `dpop` section as the package's `config/reference.conf` ships it, with
 * no variable set: the defaults a composition root layers under an
 * operator's settings. The schema holds none of its own, so a test that
 * writes a section lays its keys over this one.
 */

import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";

/** The package's defaults, as a composition root finds them. */
export const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

/** The whole file, resolved with no variable set. */
export const referenceTree = (): Record<string, unknown> =>
	parseFile(fileURLToPath(REFERENCE), { env: {} }).toObject() as Record<string, unknown>;

/** The shipped `dpop` section, with `overrides` laid over its top-level keys. */
export const shippedDpopSection = (
	overrides: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> => ({
	...(referenceTree().dpop as Record<string, unknown>),
	...overrides,
});
