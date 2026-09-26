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
 * What every device route does when the device-code store cannot be reached:
 * one answer and one kind of log line, shared so the three cannot drift.
 *
 * A store that throws — a connection gone, a timeout, a store that broke its
 * own contract — is an outage. The product answers an outage
 * `503 temporarily_unavailable` (RFC 6749 §5.2's "temporarily unable to
 * handle the request"), never a verdict on the code, which nobody could read,
 * and never a `500`, which says the server is broken when a dependency is
 * down. It is logged at error, because an outage is what an operator pages
 * on, through `loggableError`'s projection: a store error carries the command
 * it answered, and with it a user code, a device code or the approving
 * subject. The device-code store's own refusals are not outages: a
 * `DeviceCodeStoreError` is answered where it is caught.
 *
 * The projection is core's, as every log line in this package is.
 */
import { consoleLogger, loggableError } from "@o3co/auth-provider-core";
/** The body of the `503` a device route answers a store outage with. */
export const DEVICE_CODE_STORE_UNAVAILABLE = {
    error: "temporarily_unavailable",
    description: "the device authorization store is unavailable; retry later",
};
/**
 * Log a device-code store outage as `event`, at error. A logger with no error
 * channel is passed over for core's console logger, as the verification
 * route's limiter outage is, rather than losing the line.
 */
export const reportDeviceCodeStoreOutage = (logger, event, err, fields = {}) => {
    const line = { ...fields, err: loggableError(err) };
    if (typeof logger?.error === "function")
        logger.error(line, event);
    else
        consoleLogger.error(line, event);
};
