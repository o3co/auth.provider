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
 * What the federation routes log when a store, the composition or a cleanup
 * step fails: the store and step vocabulary those lines name, and the lines.
 * A line carries the error's projection, never the error.
 */
import { loggableError } from "@o3co/auth-provider-core";
/**
 * A store a federation route cannot do without could not answer: the
 * server's outage, never a verdict on the user or the IdP. One error line
 * named for the leg, with `store`, `step` and the error's projection — never
 * the error, which can carry a token record. The caller answers `503`.
 */
export const logStoreUnavailable = (log, event, store, step, cause, context = {}) => {
    log.error({ ...context, store, step, err: loggableError(cause) }, event);
};
/**
 * A federation route met a composition fault — a provider with no callback URL
 * or no redirect policy, or a `form_post` federation with no express-session
 * store on its requests. No client causes it and no retry fixes it: one line at error level,
 * `federation_misconfigured`, with the `reason`; the caller answers `500`.
 */
export const logMisconfigured = (log, reason, context = {}) => {
    log.error({ ...context, reason }, "federation_misconfigured");
};
/**
 * The warn line a best-effort step that failed is logged as,
 * `federation_cleanup_failed`: `store`, `step` and the error's projection.
 * {@link cleanUp} emits it for a step that throws; the caller of a step that
 * returns its error (the callback's discard of a refused transaction) calls
 * it directly; the login tail's reporter emits it for the steps
 * `establishSession` runs.
 */
export const logCleanupFailed = (log, store, step, cause, context = {}) => {
    log.warn({ ...context, store, step, err: loggableError(cause) }, "federation_cleanup_failed");
};
/**
 * Run one best-effort cleanup step that throws when it fails, such as a
 * rollback after a failed link. A step that fails is one
 * {@link logCleanupFailed} line; the request's own answer stands either way.
 */
export const cleanUp = async (log, store, step, run, context = {}) => {
    try {
        await run();
    }
    catch (err) {
        logCleanupFailed(log, store, step, err, context);
    }
};
