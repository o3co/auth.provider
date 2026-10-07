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
 * Every line this package writes, in three kinds (#593, D18):
 *
 * - **An outage** — a branch that answers `503`, or a `temporarily_unavailable`
 *   redirect, because a store, the key ring or the upstream could not answer:
 *   exactly one line, at error, naming what failed (`store` / `step`, or the
 *   `reason` the caller was answered with).
 * - **A failure that changed no answer** — a best-effort write, a read the
 *   answer turned out not to need, work that failed after the answer, an
 *   upstream that answered with a refusal, contention: one line, at warn.
 * - **What escaped a handler** — a bug, or a dependency failing where nothing
 *   expected it: `federation_grants_unexpected_error`, at error, with `site`.
 *
 * Every line is object-first with an event name as its message and nothing
 * after it: pino drops what follows a string. A caught error goes on it as
 * `err`, core's `loggableError` projection and never the error: the projection
 * is the redaction — what a library puts beside its message (a response body,
 * a command's arguments, a token answer on a cause) never reaches the line,
 * and an `error_description` is cut before anything token-shaped. Every
 * string field is sanitised and capped (`auditErrorText`): a grant id, a
 * connection or a client id can be what the caller sent.
 *
 * A client repository that cannot answer is written as core's one line for
 * it (`logClientRepositoryUnavailable`), with this package's `site`.
 *
 * This replaced an allowlist of field names and a closed set of error
 * classifications that predated `loggableError`: it kept a store's and an
 * upstream's error out of the log by keeping out everything but the error's
 * name, which is also what an operator needed to tell one outage from
 * another. The same limiter, client repository and upstream adapters are
 * logged through the projection by every other route of the provider.
 */
import { auditErrorText, consoleLogger, logClientRepositoryUnavailable, loggableError, } from "@o3co/auth-provider-core";
/** The line: every string sanitised and capped, `undefined` left out, the cause projected. */
function payload(fields, cause) {
    const line = {};
    for (const [key, value] of Object.entries(fields)) {
        if (value === undefined)
            continue;
        line[key] = typeof value === "string" ? auditErrorText(value) : value;
    }
    if (cause.length > 0)
        line.err = loggableError(cause[0]);
    return line;
}
/** The lines of one router, through the deployment's logger; the console's when it has none. */
export function createFederationGrantLog(given) {
    const logger = given ?? consoleLogger;
    return {
        outage: (event, fields, ...cause) => logger.error(payload(fields, cause), event),
        degraded: (event, fields, ...cause) => logger.warn(payload(fields, cause), event),
        unexpected: (site, fields, error) => logger.error(payload({ site, ...fields }, [error]), "federation_grants_unexpected_error"),
        clientRepositoryUnavailable: (site, clientId, error) => logClientRepositoryUnavailable(logger, { site, step: "find", clientId }, error),
    };
}
/**
 * `error[key]`, or `undefined` when the read throws — a getter, a Proxy's
 * trap, or `null` / `undefined`, which have nothing to read. A primitive's
 * own properties are read as any value's: none holds `expose`, `status` or
 * `type`. What classifies an error must never throw on it: a throw in the
 * routers' last error handler reaches Express's own, which answers HTML and
 * logs nothing of this package's.
 */
export const readField = (error, key) => {
    try {
        return error[key];
    }
    catch {
        return undefined;
    }
};
/** `error instanceof type`, or `false` when asking throws (a Proxy whose prototype cannot be read). */
export const isInstance = (error, type) => {
    try {
        return error instanceof type;
    }
    catch {
        return false;
    }
};
