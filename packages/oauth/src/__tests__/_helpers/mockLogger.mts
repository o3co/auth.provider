/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

import type { Logger } from "@o3co/auth-provider-core";
import { type Mock, vi } from "vitest";

/**
 * Test-only `Logger` mock. Each level + `child` is a `vi.fn()`; `child` returns
 * the same instance so spy assertions in nested handlers still resolve to the
 * same set of mock fns. Intended only for unit tests that need to satisfy the
 * `Logger` interface without standing up a real structured logger.
 */
export interface MockLogger extends Logger {
	trace: Mock;
	debug: Mock;
	info: Mock;
	warn: Mock;
	error: Mock;
	fatal: Mock;
	child: Mock;
}

export function createMockLogger(): MockLogger {
	const m: MockLogger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(() => m),
	};
	return m;
}
