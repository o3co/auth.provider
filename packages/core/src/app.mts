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
 * Re-export of the v0.5.0 boot planner createApp. The legacy v0.4.x
 * AppOptions / AppResult / createApp(options): AppResult shape was deleted
 * in Phase 9 of the v0.5.0 redesign per A2-γ §3.1.
 *
 * Consumers MUST use the new shape:
 *
 *   const handle = await createApp({ modules, bootstrapComponents });
 *   app.use(handle.router);
 *   await handle.dispose();
 *
 * See A2-β §6.3 for AppHandle shape and A2-γ §4 for the standalone
 * worked example.
 */
export {
	type AppHandle,
	type BootstrapMap,
	type CreateAppOptions,
	createApp,
	type DefaultBootstrapMap,
} from "./boot/index.mjs";
