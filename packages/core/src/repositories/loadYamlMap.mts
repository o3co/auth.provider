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

import fs from "node:fs";
// js-yaml 5 dropped the default export; import the namespace so `yaml.load`
// resolves to the named export.
import * as yaml from "js-yaml";
import type { z } from "zod";

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
	const raw = hasDocument ? yaml.load(content) : undefined;
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
