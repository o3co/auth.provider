/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { defineModule } from "../modules/manifest/index.mjs";
import { createMemoryChallengeStore } from "./adapters/memory.mjs";
import { createDefaultChallengeCeremony } from "./ceremony.mjs";

/**
 * Built-in module that provides the in-process memory ChallengeStore.
 * Per A1 §8.1.
 */
export const memoryChallengeStoreModule = defineModule({
	name: "core-challenge-store-memory",
	provides: {
		challengeStore: () => createMemoryChallengeStore(),
	},
});

/**
 * Built-in module that provides the default 3-outcome ChallengeCeremony
 * composed from challengeStore + replaySeenSet.
 *
 * Per A1 §8.1. Override path: replace this module with a custom one that
 * provides challengeCeremony from different deps; the boot planner enforces
 * provides uniqueness (BootError reason "duplicate-provides" if both are
 * added).
 */
export const defaultChallengeCeremonyModule = defineModule({
	name: "core-default-challenge-ceremony",
	requires: ["challengeStore", "replaySeenSet"] as const,
	provides: {
		challengeCeremony: (deps) =>
			createDefaultChallengeCeremony({
				challengeStore: deps.challengeStore,
				replaySeenSet: deps.replaySeenSet,
			}),
	},
});
