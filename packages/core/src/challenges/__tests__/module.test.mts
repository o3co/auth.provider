/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { defaultChallengeCeremonyModule, memoryChallengeStoreModule } from "../module.mjs";

describe("memoryChallengeStoreModule", () => {
	it("has the canonical module name 'core-challenge-store-memory'", () => {
		expect(memoryChallengeStoreModule.name).toBe("core-challenge-store-memory");
	});

	it("provides challengeStore via factory; no requires", () => {
		expect(memoryChallengeStoreModule.requires ?? []).toEqual([]);
		expect(typeof memoryChallengeStoreModule.provides?.challengeStore).toBe("function");
		const store = memoryChallengeStoreModule.provides?.challengeStore?.({} as never);
		expect((store as { kind: string }).kind).toBe("memory");
	});
});

describe("defaultChallengeCeremonyModule", () => {
	it("has the canonical module name 'core-default-challenge-ceremony'", () => {
		expect(defaultChallengeCeremonyModule.name).toBe("core-default-challenge-ceremony");
	});

	it("requires both challengeStore and replaySeenSet", () => {
		const reqs = defaultChallengeCeremonyModule.requires ?? [];
		expect(new Set(reqs)).toEqual(new Set(["challengeStore", "replaySeenSet"]));
	});

	it("provides challengeCeremony as a factory of (deps) → ChallengeCeremony", () => {
		expect(typeof defaultChallengeCeremonyModule.provides?.challengeCeremony).toBe("function");
	});
});
