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
 * Public exports for `@o3co/auth-provider-device-grant` (RFC 8628, #298).
 *
 * Deliberately NOT exported: the `DeviceCodeStore` port and the code
 * generators live in `@o3co/auth-provider-core`, so an adapter author depends
 * on core alone and never on this package. That is what lets
 * `@o3co/auth-provider-redis` ship a device-code store without taking a
 * dependency on the grant that consumes it.
 */

export {
	createDeviceAuthorizationHandler,
	type DeviceAuthorizationEndpointOptions,
} from "./deviceAuthorizationEndpoint.mjs";
export { createDeviceCodeGrant, type DeviceCodeGrantOptions } from "./grant.mjs";
export { deviceGrantConfigSchema, deviceGrantModule } from "./module.mjs";
export {
	DEVICE_CODE_GRANT_TYPE,
	DEVICE_VERIFICATION_RATE_LIMIT_PREFIX,
	type DeviceAuthorizationSettings,
	type DeviceGrantDependencies,
} from "./types.mjs";
export {
	createDeviceVerificationHandler,
	type DeviceVerificationHandlerOptions,
} from "./verificationEndpoint.mjs";
