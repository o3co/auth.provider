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
//
// INTERNAL — not exposed via the package's `exports` map. Reachable only from
// other files in this package (and its tests). See package.json `exports`.
//
import { sep } from "node:path";

const EXCLUDED_DIRS = new Set(["node_modules", "dist"]);

/**
 * Decide whether `cpSync` should copy a given source path.
 *
 * Only segments INSIDE `templateRoot` are checked against EXCLUDED_DIRS — the
 * install-prefix path above the root (e.g. `~/.npm/_npx/<hash>/node_modules/...`
 * when the package is run via `npx`) is ignored. Otherwise the filter would
 * reject every file whenever the package itself happens to live under a
 * `node_modules` directory (which is the v0.5.0 npx regression this fixes).
 *
 * NOTE: `sep` is the load-bearing platform abstraction here — DO NOT replace it
 * with a hardcoded `"/"`. On Windows `sep === "\\"` and `cpSync` passes
 * back-slash-delimited absolute paths, so segment splitting must follow the
 * platform separator.
 */
export const shouldCopyTemplateEntry = (source: string, templateRoot: string): boolean => {
	if (source === templateRoot) return true;
	const prefix = templateRoot.endsWith(sep) ? templateRoot : `${templateRoot}${sep}`;
	if (!source.startsWith(prefix)) return true;
	const rel = source.slice(prefix.length);
	return !rel.split(sep).some((s) => EXCLUDED_DIRS.has(s));
};
