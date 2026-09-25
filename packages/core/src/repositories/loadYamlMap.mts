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

/*
 * `loadYamlMap`: a YAML file of named entries (the static clients and users
 * files), each validated against a schema, as a Map.
 *
 * A file that does not parse is refused with its path, the line and column,
 * and the parser's reason — and nothing else. js-yaml's own exception quotes
 * the lines around the fault in its message and holds the whole file in
 * `mark.buffer`, and these files hold client secrets and password hashes: a
 * boot failure prints the error it ends with, cause chain and fields
 * included. So the exception is neither passed on nor kept as a `cause`, and
 * what the parser wrote into its reason from the file — an alias or a tag
 * name, which an unquoted value starting with `*` or `!` becomes — is cut off
 * (`reasonOf`).
 */

import fs from "node:fs";
// js-yaml 5 dropped the default export; import the namespace so `yaml.load`
// resolves to the named export.
import * as yaml from "js-yaml";
import type { z } from "zod";

/**
 * Where js-yaml starts quoting the input in a reason: `"` (an alias or tag
 * handle, `unidentified alias "<name>"`), `!<` (a tag, `unknown scalar tag
 * !<<tag>>`) and `: ` (`tag name cannot contain such characters: <tag>`).
 * Its fixed text never holds one; a `'` does not start a quotation there
 * (`expected ':' after a mapping key`).
 */
const QUOTED_INPUT = /"|!<|: /;

/** The reason's text before anything it quotes of the input: its first line, cut there. */
const reasonOf = (reason: unknown): string => {
	if (typeof reason !== "string") return "";
	const firstLine = reason.split(/\r?\n/, 1)[0] ?? "";
	const quoted = QUOTED_INPUT.exec(firstLine);
	return (quoted === null ? firstLine : firstLine.slice(0, quoted.index)).trim();
};

/**
 * The file's refusal: the path, the line and column (1-based, as an editor
 * counts) and the reason, from js-yaml's `reason` and `mark` — never its
 * message or its snippet. An error that is not js-yaml's names the file
 * alone.
 */
const unparseable = (filePath: string, err: unknown): Error => {
	if (!(err instanceof yaml.YAMLException)) return new Error(`Invalid YAML in ${filePath}`);
	const { mark } = err;
	const at =
		mark !== undefined && Number.isInteger(mark.line) && Number.isInteger(mark.column)
			? ` at ${mark.line + 1}:${mark.column + 1}`
			: "";
	const reason = reasonOf(err.reason);
	return new Error(`Invalid YAML in ${filePath}${at}${reason === "" ? "" : `: ${reason}`}`);
};

export const loadYamlMap = <T extends z.ZodTypeAny>(
	filePath: string,
	schema: T,
): Map<string, z.infer<T>> => {
	const content = fs.readFileSync(filePath, "utf-8");
	// js-yaml 5 throws "expected a document" on empty / whitespace / comment-only
	// input, where js-yaml 4 returned undefined. An empty config file means "no
	// entries", so treat a document-less file as an empty mapping.
	const hasDocument = content.split(/\r?\n/).some((line) => {
		const trimmed = line.trim();
		return trimmed !== "" && !trimmed.startsWith("#");
	});
	let raw: unknown;
	try {
		raw = hasDocument ? yaml.load(content) : undefined;
	} catch (err) {
		// Not the exception, and not as a `cause`: see the file header.
		throw unparseable(filePath, err);
	}
	if (raw !== null && raw !== undefined && (typeof raw !== "object" || Array.isArray(raw))) {
		throw new Error(`Invalid configuration in ${filePath}: expected a YAML mapping`);
	}
	const data = (raw ?? {}) as Record<string, unknown>;
	const map = new Map<string, z.infer<T>>();
	for (const [key, entry] of Object.entries(data)) {
		const result = schema.safeParse(entry);
		if (!result.success) {
			throw new Error(
				`Invalid entry "${key}" in ${filePath}: ${result.error.issues.map((i: z.ZodIssue) => `${i.path.join(".")}: ${i.message}`).join(", ")}`,
			);
		}
		map.set(key, result.data);
	}
	return map;
};
