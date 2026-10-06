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
 * The template's refusals before boot, as core's `BootError`: each under the
 * reason boot raises for the same case, at the stage boot raises it in
 * (`validateManifests`), so that an alert keyed on a boot error's reason sees
 * every refusal to start. The template's checks stay its own; only how a
 * refusal is reported is boot's.
 *
 * The details name a module as boot does. A key of the composition root's
 * own — the `adapters` section, the `mfaMode` switch — is named after itself,
 * as boot names core's own section "core": no module may take either name.
 */

import {
	BootError,
	type ConfigPathRelocatedDetails,
	type ConfigValidationFailedDetails,
	type EnvironmentVariableRenamedDetails,
} from "@o3co/auth-provider-core";

/** A Zod issue as `config-validation-failed` carries one: its path is the path in the configuration. */
export type ConfigIssue = ConfigValidationFailedDetails["issues"][number];

/** The stage boot raises the configuration's refusals in. */
const STAGE = "validateManifests";

/** An issue at `path` of the configuration that no schema raised: what is wrong there, in `message`. */
export function customIssue(path: readonly string[], message: string): ConfigIssue {
	return { code: "custom", path: [...path], message } as ConfigIssue;
}

/** `issues`, each with `prefix`, the path its schema read at, in front of its own path. */
export function issuesAt(prefix: readonly string[], issues: readonly ConfigIssue[]): ConfigIssue[] {
	return issues.map((issue) => ({ ...issue, path: [...prefix, ...issue.path] }) as ConfigIssue);
}

/**
 * `config-validation-failed`: `issues` at their paths, refused in the
 * sections `modules` read, each at its `schemaPath`.
 */
export function configRefused(
	message: string,
	issues: readonly ConfigIssue[],
	modules: ConfigValidationFailedDetails["modules"],
): BootError {
	return new BootError({
		message,
		reason: "config-validation-failed",
		stage: STAGE,
		details: { reason: "config-validation-failed", issues: [...issues], modules: [...modules] },
	});
}

/**
 * `config-validation-failed` for one key, at `path`, of the section `module`
 * reads at its own name: `message` is the refusal and the issue's message.
 */
export function keyRefused(message: string, module: string, path: readonly string[]): BootError {
	return configRefused(message, [customIssue(path, message)], [{ module, schemaPath: module }]);
}

/** `config-path-relocated`: each key still set at a path it moved from. */
export function pathsRelocated(
	message: string,
	relocated: ConfigPathRelocatedDetails["relocated"],
): BootError {
	return new BootError({
		message,
		reason: "config-path-relocated",
		stage: STAGE,
		details: { reason: "config-path-relocated", relocated: [...relocated] },
	});
}

/** `environment-variable-renamed`: each old variable name set, with no value. */
export function variablesRenamed(
	message: string,
	renamed: EnvironmentVariableRenamedDetails["renamed"],
): BootError {
	return new BootError({
		message,
		reason: "environment-variable-renamed",
		stage: STAGE,
		details: { reason: "environment-variable-renamed", renamed: [...renamed] },
	});
}

/** `module-section-path-invalid`: `module`'s section is read at `at`, which `problem` says it may not be. */
export function sectionPathRefused(
	message: string,
	module: string,
	at: string,
	problem: string,
): BootError {
	return new BootError({
		message,
		reason: "module-section-path-invalid",
		stage: STAGE,
		details: { reason: "module-section-path-invalid", module, at, problem },
	});
}
