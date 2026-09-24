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
		// what an operator reads. The consumers are the WebAuthn challenge
		// ceremony, the jwt-bearer registry verifier, `private_key_jwt` client
		// assertions and DPoP, which records every proof it accepts here. DPoP
		// is named as conditional on being enabled: an operator with no DPoP
		// module must not read DPoP as why their boot failed.
		const reason = memoryReplaySeenSetModule.replicaSafety?.unsafe
			? memoryReplaySeenSetModule.replicaSafety.reason
			: "";
		expect(reason).toMatch(/private_key_jwt/);
		expect(reason).toMatch(/jwt-bearer/);
		expect(reason).toMatch(/WebAuthn/);
		expect(reason).toMatch(/with DPoP enabled, a DPoP proof/);
	});
});
