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

/** Shared types for the RFC 8628 device authorization grant (#298). */

import type { AuditSink, DeviceCodeStore, RateLimiter } from "@o3co/auth-provider-core";

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

export interface DeviceAuthorizationSettings {
	/**
	 * Where the end user goes to type the code. Required when the grant is
	 * enabled — the device has nothing to display without it.
	 */
	readonly verificationUri: string;
	/**
	 * Whether to also return `verification_uri_complete`, which embeds the
	 * user code so a QR code can carry it.
	 *
	 * Off by default. RFC 8628 §5.4: with it "it is particularly important to
	 * confirm that the device is in the user's possession, as the user no
	 * longer has to type in the code" — the typing *is* the proof of
	 * proximity, and removing it without replacing that confirmation is what
	 * turns a phishing link into a working attack.
	 */
	readonly verificationUriComplete: boolean;
	readonly codeLifetimeSeconds: number;
	readonly pollingIntervalSeconds: number;
}

export interface DeviceGrantDependencies {
	readonly store: DeviceCodeStore;
	readonly settings: DeviceAuthorizationSettings;
	readonly rateLimiter?: RateLimiter;
	/**
	 * Where `device.approved` / `device.denied` / `device.rate_limited` go.
	 * Optional to wire; the module attaches `AUDIT_SINK_ABSENCE_POLICY`, so a
	 * composition with no sink has to say `audit.sink.type = "none"` (#363).
	 */
	readonly auditSink?: AuditSink;
	readonly logger?: {
		warn(obj: Record<string, unknown>, msg: string): void;
		info?(obj: Record<string, unknown>, msg: string): void;
		/**
		 * Where a limiter-backend outage is reported (#457):
		 * `rate_limiter_failed_open` / `rate_limiter_failed_closed`, the lines
		 * `createRateLimitGuard` writes. Optional so a warn-only logger keeps
		 * compiling; without it the line goes to core's console logger rather
		 * than nowhere.
		 */
		error?(obj: Record<string, unknown>, msg: string): void;
	};
	/** Injected in tests. */
	readonly now?: () => number;
}
