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
 * The `reference.conf` files a composition layers beneath its own
 * configuration (#728): core's, and each loaded module's package's, as the
 * module declares it (`section.reference`). Core names the files and reads
 * none of them — it takes no HOCON dependency; the composition root parses
 * and layers them, with the files it writes itself on top.
 */

import type { Module } from "../modules/manifest/module-spec.mjs";

/**
 * Core's own `reference.conf`: the defaults of the sections core's schema
 * declares, and the bottom of every composition's chain. Resolved from this
 * file, which sits one directory under `src/` (and so `dist/`).
 */
export const CORE_REFERENCE: URL = new URL("../../config/reference.conf", import.meta.url);

/**
 * The `reference.conf` files `modules` declare, each once, in the order a
 * composition layers them beneath its own files: every module's
 * `section.reference` in module order, then {@link CORE_REFERENCE} at the
 * bottom — also when a module declares core's own. A module that declares
 * no section, or a section with no reference, adds nothing.
 *
 * A reference that is not a `file:` URL is a `RangeError` naming the
 * module: a composition root reads each one as a file. Which of the
 * modules' packages owns a path is theirs to keep apart — each package's
 * reference holds only its own modules' sections, which each package's
 * tests hold it to (`referenceConfProblems` on the testing entry) — so the
 * order among them decides nothing.
 */
export function moduleReferences(modules: readonly Module[]): readonly URL[] {
	const references = new Map<string, URL>();
	for (const module of modules) {
		const reference: unknown = module.section?.reference;
		if (reference === undefined) continue;
		if (!(reference instanceof URL) || reference.protocol !== "file:") {
			throw new RangeError(
				`module "${module.name}": section.reference must be a file: URL naming the package's config/reference.conf`,
			);
		}
		if (reference.href === CORE_REFERENCE.href || references.has(reference.href)) continue;
		references.set(reference.href, reference);
	}
	return [...references.values(), CORE_REFERENCE];
}
