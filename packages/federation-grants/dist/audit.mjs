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
 * The `audit` seam of `RetrieveFederationGrantTokenDeps`, and what the status
 * route's backstop write goes through.
 */
export function createFederationGrantAuditBridge(options) {
    const { sink, operation, now } = options;
    return async (event) => {
        if (sink === undefined)
            return;
        const mapped = {
            timestamp: now(),
            type: event.type,
            subject: event.subject,
            clientId: event.clientId,
            ...(options.ip === undefined ? {} : { ip: options.ip }),
            ...(options.userAgent === undefined ? {} : { userAgent: options.userAgent }),
            details: {
                correlationId: event.correlationId,
                grantId: event.grantId,
                ...(event.connection === undefined ? {} : { connection: event.connection }),
                // Copies, so that a sink which holds its argument cannot be
                // handed a reference into a record core is still working with.
                // Projected, not spread: the established pair and nothing else an
                // object handed in might carry (#611).
                ...(event.upstream === undefined
                    ? {}
                    : { upstream: { issuer: event.upstream.issuer, subject: event.upstream.subject } }),
                ...(event.resource === undefined ? {} : { resource: event.resource }),
                ...(event.scopes === undefined ? {} : { scopes: [...event.scopes] }),
                outcome: event.outcome,
                operation,
            },
        };
        // A sink that throws, rejects or never answers skips no write, holds no
        // lock and delays no answer — but that is CORE's doing, not this
        // bridge's: core settles this promise, bounds the wait and reports a
        // failure through `report`. Swallowing it here made the bridge resolve,
        // so core never reached that branch and an operator learned nothing
        // about a sink that was dropping everything. The one thing this does
        // add is that a synchronous throw arrives as a rejection, so both
        // failures look the same to whoever is waiting.
        await sink.record(mapped);
    };
}
/**
 * A `.token.denied` for an exit that never reached core: a body that would not
 * parse, an authentication that failed, this provider's own throttle, a
 * request admitted as the process began to shut down.
 *
 * `clientId` and `subject` are empty until each has been established. Before
 * authentication there is a Basic username and an assertion `iss` on the
 * request, and neither has been verified — promoting one into `clientId` puts
 * an unauthenticated caller's claim into the field an operator reads as "this
 * client did it".
 */
export function routeDeniedEvent(input) {
    return {
        type: input.type ?? "federation.grant.token.denied",
        correlationId: input.correlationId,
        grantId: input.grantId,
        clientId: input.clientId ?? "",
        subject: input.subject ?? "",
        ...(input.connection === undefined ? {} : { connection: input.connection }),
        outcome: input.outcome,
    };
}
