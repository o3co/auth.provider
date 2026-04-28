/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { memoryReplaySeenSetModule } from "../module.mjs";

describe("memoryReplaySeenSetModule", () => {
	it("has the canonical module name 'core-replay-seen-set-memory'", () => {
		expect(memoryReplaySeenSetModule.name).toBe("core-replay-seen-set-memory");
	});

	it("provides replaySeenSet via factory; no requires", () => {
		expect(memoryReplaySeenSetModule.requires ?? []).toEqual([]);
		expect(typeof memoryReplaySeenSetModule.provides?.replaySeenSet).toBe("function");
		const set = memoryReplaySeenSetModule.provides?.replaySeenSet?.({} as never);
		expect((set as { kind: string }).kind).toBe("memory");
	});
});
