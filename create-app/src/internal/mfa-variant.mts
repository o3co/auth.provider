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
// INTERNAL — not exposed via the package's `exports` map.
//
// A scaffold with MFA or without it, from one template. The template says what
// is MFA's; this module only applies what it says:
//
// - `<name>.no-mfa.<ext>` is the twin of `<name>.<ext>`: without MFA it takes
//   the target's place; with MFA it is dropped. A twin with no target is
//   refused.
// - A line holding `no-mfa:omit-file` omits its whole file without MFA.
// - Lines from one holding `no-mfa:omit-begin` to one holding
//   `no-mfa:omit-end` are omitted without MFA; blocks do not nest.
//
// Marker lines are dropped either way. A marker it cannot read refuses the
// scaffold, naming the file, before any file changes.
//
import { readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

const OMIT_FILE = "no-mfa:omit-file";
const OMIT_BEGIN = "no-mfa:omit-begin";
const OMIT_END = "no-mfa:omit-end";
const MARKER = /no-mfa:omit-[a-z]*/;
const TWIN = /^(.+)\.no-mfa(\.[^.]+)?$/;

/** The file `name` is the twin of, in the same directory; `undefined` when it is none. */
export const twinTarget = (name: string): string | undefined => {
	const match = TWIN.exec(name);
	return match === null ? undefined : `${match[1]}${match[2] ?? ""}`;
};

/**
 * `text` as a scaffold with MFA (`mfa`) or without it holds it, its marker
 * lines dropped; `undefined` when the scaffold omits the file. `file` names it
 * in a refusal.
 */
export const variantText = (text: string, mfa: boolean, file: string): string | undefined => {
	if (!MARKER.test(text)) return text;
	const kept: string[] = [];
	let omitFile = false;
	let inBlock = false;
	for (const line of text.split("\n")) {
		const marker = MARKER.exec(line)?.[0];
		if (marker === undefined) {
			if (mfa || !inBlock) kept.push(line);
			continue;
		}
		if (marker === OMIT_FILE && !inBlock) {
			omitFile = true;
		} else if (marker === OMIT_BEGIN && !inBlock) {
			inBlock = true;
		} else if (marker === OMIT_END && inBlock) {
			inBlock = false;
		} else {
			throw new Error(`${file}: "${line.trim()}" is not a marker that can stand here`);
		}
	}
	if (inBlock) throw new Error(`${file}: ${OMIT_BEGIN} has no ${OMIT_END}`);
	return !mfa && omitFile ? undefined : kept.join("\n");
};

/** Every file under `dir`, absolute. */
const filesUnder = (dir: string): string[] =>
	readdirSync(dir, { recursive: true, withFileTypes: true })
		.filter((entry) => entry.isFile())
		.map((entry) => join(entry.parentPath, entry.name));

/**
 * Make the scaffold at `targetDir` the one with MFA (`mfa`) or without it,
 * by the twins and markers its files hold.
 */
export const applyMfaVariant = (targetDir: string, mfa: boolean): void => {
	const files = filesUnder(targetDir);
	const name = (file: string): string => relative(targetDir, file).split(sep).join("/");
	const present = new Set(files);

	// Everything is read and checked first, so a refusal changes nothing.
	const twins: [string, string][] = [];
	const texts: [string, string | undefined][] = [];
	for (const file of files) {
		const target = twinTarget(file.slice(file.lastIndexOf(sep) + 1));
		if (target !== undefined) {
			const targetFile = join(file, "..", target);
			if (!present.has(targetFile)) {
				throw new Error(`${name(file)} is the twin of ${name(targetFile)}, which is not there`);
			}
			twins.push([file, targetFile]);
			continue;
		}
		const text = readFileSync(file, "utf-8");
		if (MARKER.test(text)) texts.push([file, variantText(text, mfa, name(file))]);
	}

	for (const [file, text] of texts) {
		if (text === undefined) rmSync(file);
		else writeFileSync(file, text);
	}
	for (const [twin, target] of twins) {
		if (mfa) rmSync(twin);
		else renameSync(twin, target);
	}
};
