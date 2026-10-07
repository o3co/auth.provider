/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * The in-process limiter's section, `core-rate-limiter-memory`, as core's
 * `config/reference.conf` ships it with no optional variable set: the
 * defaults a composition root layers beneath its own files. The section's
 * schema fills none of its own, so a test that writes the section, or boots
 * the module, lays its keys over this one.
 */

import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";

const REFERENCE_CONF_PATH = fileURLToPath(
	new URL("../../../config/reference.conf", import.meta.url),
);

/** The substitutions core's `reference.conf` cannot resolve without. */
const REQUIRED_ENV = {
	OAUTH_JWT_SECRET: "shipped-section.at-least-32-bytes.of-secret",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "shipped-section-session.at-least-32-bytes.ok",
};

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** `over` laid over `under` as one HOCON file over another: objects merged key by key, any other value replaced. */
function layered(under: unknown, over: unknown): unknown {
	if (!isPlainObject(under) || !isPlainObject(over)) return over;
	const merged: Record<string, unknown> = { ...under };
	for (const [key, value] of Object.entries(over)) merged[key] = layered(under[key], value);
	return merged;
}

/** The shipped `core-rate-limiter-memory` section, with `overrides` laid over it. */
export function shippedMemoryRateLimiterSection(
	overrides: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> {
	const tree = parseFile(REFERENCE_CONF_PATH, { env: REQUIRED_ENV }).toObject() as Record<
		string,
		unknown
	>;
	return layered(tree["core-rate-limiter-memory"], overrides) as Record<string, unknown>;
}
