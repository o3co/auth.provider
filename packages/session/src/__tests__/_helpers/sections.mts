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
 * The package's sections in a configuration built by hand: the captures boot
 * requires of the variables the session and session-store modules declare
 * renamed, and the session store's section with a change laid over it.
 */

import { renamedVariableCaptures } from "@o3co/auth-provider-core/testing";
import { sessionModule } from "#/module.mjs";
import { sessionStoreModule } from "#/modules/sessionStoreModule.mjs";

/**
 * `config` with what a resolution of the package's reference under an
 * environment that sets none of its variables captures of the names its
 * modules declare renamed (`null` each), beside what `config` already
 * captures: what boot requires of a configuration handed to a composition
 * that loads either module.
 */
export function withSessionCaptures<C extends object>(config: C): C {
	const captured = (config as { "renamed-variables"?: Record<string, unknown> })[
		"renamed-variables"
	];
	return {
		...config,
		"renamed-variables": {
			...captured,
			...renamedVariableCaptures({ modules: [sessionModule, sessionStoreModule], env: {} }),
		},
	};
}

/** `config` with `change` laid over its session store's section, `session-store`. */
export function withStore<C extends object>(config: C, change: Record<string, unknown>): C {
	const store = (config as { "session-store"?: Record<string, unknown> })["session-store"];
	return { ...config, "session-store": { ...store, ...change } };
}

/** `config` with `change` laid over the session module's section, `session`. */
export function withSession<C extends object>(config: C, change: Record<string, unknown>): C {
	const section = (config as { session?: Record<string, unknown> }).session;
	return { ...config, session: { ...section, ...change } };
}
