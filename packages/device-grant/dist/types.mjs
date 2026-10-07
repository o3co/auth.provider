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
/** The grant type URN. RFC 8628 §3.4. */
export const DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
/**
 * Key prefix this package rate-limits the verification endpoint under.
 * Defined in core beside the seed that reads `oauth.deviceAuthorization.rateLimit`,
 * so the endpoint and the seed cannot spell the prefix differently.
 */
export { DEVICE_VERIFICATION_RATE_LIMIT_PREFIX } from "@o3co/auth-provider-core";
/**
 * Key prefix `POST /oauth/device_authorization` is throttled under, keyed
 * `device_authorization:ip:<ip>` by `createRateLimitGuard` like the other
 * public entry points (`token`, `authorize`, `introspect`).
 */
export const DEVICE_AUTHORIZATION_RATE_LIMIT_PREFIX = "device_authorization";
