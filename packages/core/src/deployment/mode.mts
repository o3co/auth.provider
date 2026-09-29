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

/**
 * The one reading of the configuration's `deployment.mode`: what boot fills
 * the `deploymentMode` slot with before any provider runs, and what the
 * replica-safety guard decides by. Every other reader requires the slot.
 */

import type { DeploymentMode } from "./types.mjs";

/**
 * `single` or `multi` as `deployment.mode` states it, `unset` for anything
 * else — absence included. Core's schema admits only the two, or none; any
 * other value reaches here only through a configuration the schema never
 * saw, and reads as the mode that warns rather than the one that is silent.
 */
export function deploymentModeOf(config: unknown): DeploymentMode {
	const mode = (config as { deployment?: { mode?: unknown } } | undefined)?.deployment?.mode;
	return mode === "single" || mode === "multi" ? mode : "unset";
}
