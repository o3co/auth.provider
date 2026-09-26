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
import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { configuredMaxEntries } from "../single-use/max-entries.mjs";
import { createMemoryReplaySeenSet } from "./adapters/memory.mjs";
import type { ReplaySeenSet } from "./types.mjs";

/**
 * Domain-specific AdapterFactory alias for ReplaySeenSet.
 * Per A1 §5.6.
 */
export type ReplaySeenSetFactory = AdapterFactory<ReplaySeenSet>;

export function createReplaySeenSetFactory(): ReplaySeenSetFactory {
	return createAdapterFactory<ReplaySeenSet>("ReplaySeenSet");
}

/**
 * Register the in-tree built-in builders: `memory`, capped at the adapter
 * config's `maxEntries` (`factory.create({ type: "memory", maxEntries })`,
 * read as `replaySeenSet.memory.maxEntries` is: absent means the default, a
 * value it cannot use is a RangeError naming the key).
 */
export function registerBuiltinReplaySeenSets(factory: ReplaySeenSetFactory): void {
	factory.register("memory", (config) =>
		createMemoryReplaySeenSet(
			configuredMaxEntries(config.maxEntries, "ReplaySeenSet memory adapter maxEntries"),
		),
	);
}
