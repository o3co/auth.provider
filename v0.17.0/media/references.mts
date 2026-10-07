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
 * configuration: core's, and each loaded module's package's, as the
 * module declares it (`section.reference`). Core names the files and reads
 * none of them — it takes no HOCON dependency; the composition root parses
 * and layers them, with the files it writes itself on top.
 */

import type { Module } from "../modules/manifest/module-spec.mjs";

/** Core's own `reference.conf`, resolved from this file, which sits one directory under `src/` (and so `dist/`). */
const CORE_REFERENCE_HREF: string = new URL("../../config/reference.conf", import.meta.url).href;

/**
 * Core's own `reference.conf`: the defaults of the sections core's schema
 * declares, and the bottom of every composition's chain. A new `URL` on
 * every call — a `URL` can be changed in place, and one shared object would
 * carry a change made through it to every later caller.
 */
export function coreReference(): URL {
	return new URL(CORE_REFERENCE_HREF);
}

/**
 * The `reference.conf` files `modules` declare, each once, in the order a
 * composition layers them beneath its own files: every module's
 * `section.reference` in module order, then {@link coreReference} at the
 * bottom (also when a module declares core's own). Each is a new `URL`, so
 * changing an answer changes neither the manifest nor a later answer.
 *
 * Fold them beneath the composition's own files in this order
 * (`own.withFallback(first).withFallback(second)…`, core's last), so where
 * two set the same path the earlier wins and core's loses to every
 * package's. The shipped references are disjoint (each package's tests hold
 * its reference to its own modules' sections via `packageReferenceProblems`,
 * and core's tests hold them disjoint), so the order among the packages
 * decides nothing today.
 *
 * A reference that is not a `file:` URL is a `RangeError` naming the
 * module: a composition root reads each one as a file.
 */
export function moduleReferences(modules: readonly Module[]): readonly URL[] {
	const references = new Set<string>();
	for (const module of modules) {
		const reference: unknown = module.section?.reference;
		if (reference === undefined) continue;
		if (!(reference instanceof URL) || reference.protocol !== "file:") {
			throw new RangeError(
				`module "${module.name}": section.reference must be a file: URL naming the package's config/reference.conf`,
			);
		}
		if (reference.href !== CORE_REFERENCE_HREF) references.add(reference.href);
	}
	return [...references, CORE_REFERENCE_HREF].map((href) => new URL(href));
}
