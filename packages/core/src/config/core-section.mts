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
 * Core's own section, `core {}`, read from a resolved configuration no
 * schema has parsed yet: what a composition root reads of core's settings
 * before it knows its modules, by the strict schema boot parses the section
 * with, and nothing of any other section.
 */

import { z } from "zod";
import { type CoreConfig, CoreConfigSchema } from "./application.schema.mjs";
import { parsedOrRefused } from "./composed.mjs";

/** Core's own section, `core {}`, as its schema parses it. */
export type CoreSection = NonNullable<CoreConfig["core"]>;

/** The configuration with core's section alone declared; every other section is not read. */
const CoreSectionReader = z.object({ core: CoreConfigSchema.shape.core });

/**
 * `core {}` of `raw`, parsed by the schema boot parses it with: strict at
 * every level, a variable's string coerced as boot coerces it. An absent
 * section is an empty one. No other section is parsed or refused here; each
 * is its module's to read.
 *
 * @throws RangeError naming each refused path (`core.…`, or the
 *   configuration itself when it is not an object) — an unknown key by its
 *   name, never its value — with the schema's error as its `cause`; a read
 *   that throws is refused the same way, carrying what it threw.
 */
export function readCoreSection(raw: unknown): CoreSection {
	return parsedOrRefused(CoreSectionReader, raw).core ?? {};
}
