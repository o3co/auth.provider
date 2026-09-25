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
		// what an operator reads, and it names exactly what records here:
		// `private_key_jwt` client assertions, the WebAuthn challenge ceremony
		// (a consumed challenge is marked seen), DPoP, which records every proof
		// it accepts, and the jwt-bearer registry verifier for an ID-JAG only —
		// a plain RFC 7523 assertion's `jti` is never recorded, so "a jwt-bearer
		// assertion" would name something that does not fork. DPoP is named as
		// conditional on being enabled: an operator with no DPoP module must
		// not read DPoP as why their boot failed.
		const reason = memoryReplaySeenSetModule.replicaSafety?.unsafe
			? memoryReplaySeenSetModule.replicaSafety.reason
			: "";
		expect(reason).toMatch(/a private_key_jwt client assertion/);
		expect(reason).toMatch(/the jti of an ID-JAG \(jwt-bearer\) assertion/);
		expect(reason).not.toMatch(/, a jwt-bearer assertion/);
		expect(reason).toMatch(/a consumed WebAuthn challenge/);
		expect(reason).toMatch(/with DPoP enabled, a DPoP proof/);
	});
});
