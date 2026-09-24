/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

// The shared container's start: what it retries, and that a failed attempt's
// container is always removed. Against fakes — the real start is what every
// Redis-backed file in this package already exercises.

import type { StartedTestContainer } from "testcontainers";
import { describe, expect, it, vi } from "vitest";
import { startDiscardingFailures } from "./redis-container.global.mjs";

const portsNotBound = () =>
	new Error("Timed out after 10000ms while waiting for container ports to be bound to the host");
const started = { getHost: () => "127.0.0.1" } as unknown as StartedTestContainer;

describe("startDiscardingFailures", () => {
	it("retries the port-binding timeout, removing each failed attempt's container first", async () => {
		const labels: string[] = [];
		const attempt = vi.fn(async (label: string) => {
			labels.push(label);
			if (labels.length < 3) throw portsNotBound();
			return started;
		});
		const discard = vi.fn(async () => {});

		expect(await startDiscardingFailures(attempt, discard)).toBe(started);
		expect(attempt).toHaveBeenCalledTimes(3);
		// Each attempt is labelled on its own, and exactly the failed ones are removed.
		expect(new Set(labels).size).toBe(3);
		expect(discard.mock.calls.map(([label]) => label)).toEqual(labels.slice(0, 2));
	});

	it("gives up after the last attempt, having removed its container too", async () => {
		const attempt = vi.fn(async () => {
			throw portsNotBound();
		});
		const discard = vi.fn(async () => {});

		await expect(startDiscardingFailures(attempt, discard, 3)).rejects.toThrow(/ports to be bound/);
		expect(attempt).toHaveBeenCalledTimes(3);
		expect(discard).toHaveBeenCalledTimes(3);
	});

	it("does not retry any other failure, and still removes what it started", async () => {
		const attempt = vi.fn(async () => {
			throw new Error("image not found");
		});
		const discard = vi.fn(async () => {});

		await expect(startDiscardingFailures(attempt, discard)).rejects.toThrow("image not found");
		expect(attempt).toHaveBeenCalledTimes(1);
		expect(discard).toHaveBeenCalledTimes(1);
	});

	it("reports the start's own failure when the removal fails too", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const attempt = vi.fn(async () => {
			throw new Error("image not found");
		});
		const discard = vi.fn(async () => {
			throw new Error("daemon gone");
		});

		await expect(startDiscardingFailures(attempt, discard)).rejects.toThrow("image not found");
		expect(warn).toHaveBeenCalledWith(expect.stringContaining("daemon gone"));
		warn.mockRestore();
	});
});
