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

/** Shared types for the RFC 8628 device authorization grant. */

import type { AuditSink, DeviceCodeStore } from "@o3co/auth-provider-core";

/** The grant type URN. RFC 8628 §3.4. */
export const DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

/** The tag the verification endpoint counts attempts under. */
export { DEVICE_VERIFICATION_ATTEMPT_TAG } from "./verificationAttempts.mjs";

/**
 * Key prefix `POST /oauth/device_authorization` is throttled under when a
 * rate limiter is wired, keyed `device_authorization:ip:<ip>` by
 * `createRateLimitGuard` like the other public entry points (`token`,
 * `authorize`, `introspect`).
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
	 * user code so a QR code can carry it. Off by default: typing the code is
	 * the proof of proximity (RFC 8628 §5.4). See README,
	 * "`verification_uri_complete` is off by default".
	 */
	readonly verificationUriComplete: boolean;
	readonly codeLifetimeSeconds: number;
	readonly pollingIntervalSeconds: number;
}

export interface DeviceGrantDependencies {
	readonly store: DeviceCodeStore;
	readonly settings: DeviceAuthorizationSettings;
	/**
	 * Where `device.approved` / `device.denied` / `device.rate_limited` /
	 * `device.decision_outcome_unknown` go. Optional to wire; the module
	 * attaches `AUDIT_SINK_ABSENCE_POLICY`, so a composition with no sink has
	 * to list `auditSink` in `core.declaredAbsent`.
	 */
	readonly auditSink?: AuditSink;
	readonly logger?: {
		warn(obj: Record<string, unknown>, msg: string): void;
		info?(obj: Record<string, unknown>, msg: string): void;
		/**
		 * Where an outage is reported (an attempt counter's
		 * `attempt_counter_unavailable`, a session-admission outage). Optional
		 * so a warn-only logger keeps compiling; without it the line goes to
		 * core's console logger.
		 */
		error?(obj: Record<string, unknown>, msg: string): void;
	};
	/** Injected in tests. */
	readonly now?: () => number;
}
