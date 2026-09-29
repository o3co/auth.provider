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
 * Only segments inside `templateRoot` are checked against EXCLUDED_DIRS; the
 * install prefix above it (e.g. `~/.npm/_npx/<hash>/node_modules/...` under
 * `npx`) is ignored, or every file would be rejected whenever the package
 * itself lives under a `node_modules` directory.
 *
 * `pathSep` lets tests exercise POSIX and Windows separators on any host.
 * Production callers keep the `path.sep` default: `cpSync` passes
 * backslash-delimited paths on Windows.
 */
export const shouldCopyTemplateEntry = (
	source: string,
	templateRoot: string,
	pathSep: string = sep,
): boolean => {
	if (source === templateRoot) return true;
	const prefix = templateRoot.endsWith(pathSep) ? templateRoot : `${templateRoot}${pathSep}`;
	if (!source.startsWith(prefix)) return true;
	const rel = source.slice(prefix.length);
	return !rel.split(pathSep).some((s) => EXCLUDED_DIRS.has(s));
};
