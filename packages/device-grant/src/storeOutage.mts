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
 * What every device route does when the device-code store cannot be
 * reached: one answer and one kind of log line, shared so the three routes
 * cannot drift.
 *
 * A store that throws is an outage, answered `503 temporarily_unavailable`
 * (RFC 6749 §5.2): never a verdict on a code nobody could read, and never a
 * `500`, which says the server is broken when a dependency is down. It is
 * logged at error, for an operator to page on, through core's
 * `loggableError` projection, because a store error carries the command it
 * answered and with it a user code, a device code or the approving subject.
 * A `DeviceCodeStoreError` is the store's own refusal, not an outage, and is
 * answered where it is caught.
 *
 * A record the store answered that core's `readDeviceAuthorization` refuses,
 * or a wrapper around it that `storeAnswer.mts` refuses, is logged the same
 * way, naming the field and never its value; each route decides what it
 * answers for it.
 */
import type { DeviceAuthorizationReading } from "@o3co/auth-provider-core";
import { consoleLogger, loggableError } from "@o3co/auth-provider-core";
import type { StoreAnswerRefusal } from "./storeAnswer.mjs";

/** The body of the `503` a device route answers a store outage with. */
export const DEVICE_CODE_STORE_UNAVAILABLE = {
	error: "temporarily_unavailable",
	description: "the device authorization store is unavailable; retry later",
} as const;

/**
 * Log a device-code store outage as `event`, at error. A logger with no error
 * channel is passed over for core's console logger, as the verification
 * route's limiter outage is, rather than losing the line.
 */
export const reportDeviceCodeStoreOutage = (
	logger: { error?(obj: Record<string, unknown>, msg: string): void } | undefined,
	event: string,
	err: unknown,
	fields: Record<string, unknown> = {},
): void => {
	const line = { ...fields, err: loggableError(err) };
	if (typeof logger?.error === "function") logger.error(line, event);
	else consoleLogger.error(line, event);
};

/** A refusal `readDeviceAuthorization` answered. */
export type DeviceAuthorizationRefusal = Exclude<DeviceAuthorizationReading, { readonly ok: true }>;

/**
 * Log a record the store answered that `readDeviceAuthorization` refused, or
 * a wrapper around it that `storeAnswer.mts` refused, as `event`, at error,
 * with the logger fallback an outage has.
 */
export const reportUnreadableDeviceAuthorization = (
	logger: { error?(obj: Record<string, unknown>, msg: string): void } | undefined,
	event: string,
	refusal: DeviceAuthorizationRefusal | StoreAnswerRefusal,
	fields: Record<string, unknown> = {},
): void => {
	const line = {
		...fields,
		refused: refusal.refused,
		...("field" in refusal ? { field: refusal.field } : {}),
	};
	if (typeof logger?.error === "function") logger.error(line, event);
	else consoleLogger.error(line, event);
};
