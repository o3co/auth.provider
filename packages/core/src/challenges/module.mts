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
import { z } from "zod";
import { coreReference } from "../config/references.mjs";
import { defineModule } from "../modules/manifest/index.mjs";
import { configuredMaxEntries } from "../single-use/max-entries.mjs";
import { createMemoryChallengeStore } from "./adapters/memory.mjs";
import { createChallengeCeremony } from "./ceremony.mjs";

/**
 * Built-in module that provides the in-process memory ChallengeStore, capped
 * at `core-challenge-store-memory.maxEntries`, its own section, when the
 * config sets it (the adapter's default otherwise); a value that is not a
 * positive whole number refuses the boot, naming the key. The section is
 * strict; `challengeStore.memory`, its old path, refuses boot naming it.
 */
export const memoryChallengeStoreModule = defineModule({
	name: "core-challenge-store-memory",
	section: {
		schema: z.object({ maxEntries: z.unknown().optional() }).strict().optional(),
		reference: coreReference(),
		relocatedFrom: { "challengeStore.memory": { to: "", environmentVariable: null } },
	},
	// What forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"WebAuthn challenges fork per replica — a ceremony started on one replica cannot be completed on another",
	},
	provides: {
		challengeStore: ({ section }) =>
			createMemoryChallengeStore(
				configuredMaxEntries(section?.maxEntries, "core-challenge-store-memory.maxEntries"),
			),
	},
});

/**
 * Built-in module that provides the default 3-outcome ChallengeCeremony
 * composed from challengeStore + replaySeenSet.
 *
 * Override path: replace this module with a custom one that provides
 * challengeCeremony from different deps; the boot planner enforces provides
 * uniqueness (BootError reason "duplicate-provides" if both are added).
 */
export const defaultChallengeCeremonyModule = defineModule({
	name: "core-default-challenge-ceremony",
	requires: ["challengeStore", "replaySeenSet"] as const,
	provides: {
		challengeCeremony: (deps) =>
			createChallengeCeremony({
				challengeStore: deps.challengeStore,
				replaySeenSet: deps.replaySeenSet,
			}),
	},
});
