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
 * How the deployment runs, as two slots whose contracts are core's (#728):
 * what every module's HTTP behaviour depends on of the `http` module's
 * settings (`httpSettings`), and how many replicas the operator says run
 * (`deploymentMode`). A module requires the slot rather than reading
 * `http {}` or `deployment.mode` from the configuration.
 *
 * The contract suites, and a test double for `httpSettings`, are published
 * on `@o3co/auth-provider-core/testing`. Types only.
 */

/**
 * What the `http` module owns that the rest of the deployment's HTTP
 * behaviour depends on.
 */
export interface HttpSettings {
	/**
	 * `http.trustProxy`, as Express's `trust proxy` takes it: `false` (the
	 * socket peer is `req.ip`), `true` (every hop), a hop count, or a list of
	 * addresses, ranges and named ranges (`net/trusted-proxy.mts`). What
	 * every module reads through `req.ip` and `req.protocol` depends on it.
	 */
	readonly trustProxy: boolean | number | readonly string[];
	readonly cors: {
		/**
		 * The browser origins core's CORS middleware lets read the token,
		 * userinfo, revocation, discovery and JWKS responses (#500): serialized
		 * origins; empty, CORS is off. Never a CSRF trust list.
		 */
		readonly allowedOrigins: readonly string[];
	};
}

/**
 * How many replicas the operator says this deployment runs (#271):
 * `single` or `multi` as `deployment.mode` states it, `unset` when it
 * states nothing — the state in which a module that holds per-process
 * state warns rather than refuses.
 */
export type DeploymentMode = "single" | "multi" | "unset";

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** What the deployment's HTTP behaviour depends on of the `http` module's settings (#728): provided by that module. */
		readonly httpSettings?: HttpSettings;
		/**
		 * How many replicas run (#728): core is to fill it from `core.deployment.mode`
		 * for every composition, as it fills the synthetic keys, and the key is
		 * to be reserved when it does.
		 */
		readonly deploymentMode?: DeploymentMode;
	}
}
