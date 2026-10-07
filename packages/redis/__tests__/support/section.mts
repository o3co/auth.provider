/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { fileURLToPath } from "node:url";
import type { Module } from "@o3co/auth-provider-core";
import { renamedVariableCaptures } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** `over` laid over `under` as one HOCON file over another: objects merged key by key, any other value replaced. */
function layered(under: unknown, over: unknown): unknown {
	if (over === undefined) return under;
	if (!isPlainObject(under) || !isPlainObject(over)) return over;
	const merged: Record<string, unknown> = { ...under };
	for (const [key, value] of Object.entries(over)) merged[key] = layered(under[key], value);
	return merged;
}

/**
 * `module`'s section as its package's `config/reference.conf` ships it,
 * resolved with no variable set: the defaults a composition root layers
 * beneath the deployment's files. The schemas hold none of their own.
 */
export function shippedSection(module: Module): unknown {
	const reference = module.section?.reference;
	if (reference === undefined) return undefined;
	const tree = parseFile(fileURLToPath(reference), { env: {} }).toObject() as Record<
		string,
		unknown
	>;
	return tree[module.name];
}

/** `section` laid over `module`'s section as its package's `reference.conf` ships it. */
export function overShipped(module: Module, section: unknown): unknown {
	return layered(shippedSection(module), section);
}

/**
 * `config` with each of the modules' sections laid over the one its
 * package's `config/reference.conf` ships, as a composition root layers the
 * file beneath its own.
 */
export function overReference(
	config: Readonly<Record<string, unknown>>,
	modules: readonly Module[],
): Record<string, unknown> {
	const sections = modules.map((module) => [
		module.name,
		layered(shippedSection(module), config[module.name]),
	]);
	return {
		...config,
		...Object.fromEntries(sections.filter(([, section]) => section !== undefined)),
	};
}

/**
 * `deps` as boot hands them to a factory of `module`: with its own section,
 * parsed with its schema from `deps.config` at the section's path (the
 * module's name), laid over the section the package's `reference.conf`
 * ships. A module with no section gets `deps` unchanged.
 */
export function withSection(
	module: Module,
	deps: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
	if (module.section === undefined) return { ...deps };
	const config = deps.config as Readonly<Record<string, unknown>> | undefined;
	return {
		...deps,
		section: module.section.schema.parse(layered(shippedSection(module), config?.[module.name])),
	};
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
