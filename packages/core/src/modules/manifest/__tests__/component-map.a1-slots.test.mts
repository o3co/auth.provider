/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expectTypeOf, it } from "vitest";
import type { ChallengeCeremony, ChallengeStore } from "../../../challenges/types.mjs";
import type { ReplaySeenSet } from "../../../replay-seen-set/types.mjs";
import type { ComponentMap } from "../component-map.mjs";

describe("ComponentMap — the challenge and replay slots", () => {
	it("exposes optional challengeStore slot of ChallengeStore type", () => {
		expectTypeOf<ComponentMap["challengeStore"]>().toEqualTypeOf<ChallengeStore | undefined>();
	});

	it("exposes optional replaySeenSet slot of ReplaySeenSet type", () => {
		expectTypeOf<ComponentMap["replaySeenSet"]>().toEqualTypeOf<ReplaySeenSet | undefined>();
	});

	it("exposes optional challengeCeremony slot of ChallengeCeremony type", () => {
		expectTypeOf<ComponentMap["challengeCeremony"]>().toEqualTypeOf<
			ChallengeCeremony | undefined
		>();
	});
});
