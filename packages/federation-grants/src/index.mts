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
 * Public exports for `@o3co/auth-provider-federation-grants` (#593).
 *
 * Deliberately NOT exported: the `FederationGrantStore` port, the grant domain
 * types and `retrieveFederationGrantToken` all live in
 * `@o3co/auth-provider-core`. A store adapter depends on core alone and never
 * on this package — which is what lets `@o3co/auth-provider-redis` ship a
 * federation grant store without taking a dependency on the routes that spend
 * one, and what lets a logout revoke grants through the port with these routes
 * not installed at all.
 *
 * Also not exported: the HTTP serialization, the body parser, the audit bridge
 * and the connection resolver. They are how these two routes are spelled, not
 * a second HTTP convention for the product — and a composition root that
 * needed one of them directly would be building a route this package should
 * have built.
 *
 * `createFederationGrantRouter` IS exported, because a root that mounts the
 * handlers itself needs the middleware chain rather than an approximation of
 * it: the order — correlation, then the throttle, then parsing, then client
 * authentication — is the security property.
 */

export {
	createFederationGrantBackground,
	type FederationGrantBackground,
} from "./background.mjs";
export {
	federationGrantBackgroundModule,
	federationGrantsConfigSchema,
	federationGrantsModule,
	federationGrantsModules,
} from "./module.mjs";
export {
	createDisabledFederationGrantRouter,
	createFederationGrantRouter,
	FEDERATION_GRANTS_RATE_LIMIT_PREFIX,
	type FederationGrantRouterOptions,
} from "./routes.mjs";
export {
	createFederationGrantTokenHandler,
	type FederationGrantTokenHandlerOptions,
} from "./tokenRoute.mjs";
export { FEDERATION_GRANTS_MOUNT_PATH } from "./types.mjs";
