/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import type { Module } from "@o3co/auth-provider-core";
import { renamedVariableCaptures } from "@o3co/auth-provider-core/testing";

/**
 * `deps` as boot hands them to a factory of `module`: with its own section,
 * parsed with its schema from `deps.config` at the section's path (the
 * module's name). A module with no section gets `deps` unchanged.
 */
export function withSection(
	module: Module,
	deps: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
	if (module.section === undefined) return { ...deps };
	const config = deps.config as Readonly<Record<string, unknown>> | undefined;
	return { ...deps, section: module.section.schema.parse(config?.[module.name]) };
}

/**
 * `config` with what a resolution of the modules' references under an
 * environment that sets none of their variables captures of the names they
 * declare renamed (`null` each), beside what `config` already captures.
 */
export function capturing(
	config: Readonly<Record<string, unknown>>,
	modules: readonly Module[],
): Record<string, unknown> {
	const captured = config["renamed-variables"] as Readonly<Record<string, unknown>> | undefined;
	return {
		...config,
		"renamed-variables": { ...captured, ...renamedVariableCaptures({ modules, env: {} }) },
	};
}
