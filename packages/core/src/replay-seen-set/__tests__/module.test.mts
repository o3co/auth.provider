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

	it("names what actually forks when it refuses a multi-replica boot", () => {
		// The reason is quoted verbatim into the refused boot message, so it is
		// what an operator reads. It said DPoP proof replay — but DPoP keeps its
		// own `dpopReplayStore` and never touches this slot. The consumers are
		// the WebAuthn challenge ceremony, the jwt-bearer registry verifier and
		// `private_key_jwt` client assertions, and an operator with no DPoP
		// module was told DPoP was why their boot failed.
		const reason = memoryReplaySeenSetModule.replicaSafety?.unsafe
			? memoryReplaySeenSetModule.replicaSafety.reason
			: "";
		expect(reason).not.toMatch(/DPoP/);
		expect(reason).toMatch(/private_key_jwt/);
		expect(reason).toMatch(/jwt-bearer/);
		expect(reason).toMatch(/WebAuthn/);
	});
});
