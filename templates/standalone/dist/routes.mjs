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
/*
 * The host's routes, in the order `app.mts` mounts them: liveness, readiness
 * and the metrics scrape ahead of the composed auth router — so they keep
 * answering while the auth pipeline is degraded, which is when an operator
 * needs them — then that router, then core's terminal error handler, last,
 * because Express hands an error only to handlers mounted after the route
 * that raised it. A function rather than inline in `app.mts`, so the order
 * and the handler can be tested as the process mounts them.
 *
 * The handler is core's `terminalErrorHandler`, the one that already ends
 * the composed router, so an error one of the host's routes lets through
 * is answered as every other route's is: `500 server_error` /
 * `unexpected_error` in the RFC 6749 envelope with `Cache-Control:
 * no-store`, logged once as `unhandled_request_error` with the path through
 * `auditErrorText` and the error's `loggableError` projection; a refusal an
 * `http-errors` error marks as the client's keeps its 4xx; a response whose
 * headers already went out is closed rather than handed to Express's final
 * handler, which would print the stack.
 */
import { createHealthcheckRouter, createReadinessRouter, terminalErrorHandler, } from "@o3co/auth-provider-core";
import express from "express";
/** Mount the host's routes, the composed router and the terminal error handler on `app`. */
export function mountRoutes(app, options) {
    // Liveness: the process is up and its event loop is turning. Deliberately
    // static — restarting the process would not bring Redis back, so a Redis
    // outage must not read as "this container is broken, kill it".
    app.use(createHealthcheckRouter(express));
    // Readiness: can this replica serve right now? Redis backs sessions,
    // authorization codes and refresh-token families in the deployable
    // defaults, so a replica that has lost it answers 503 here and should be
    // taken out of rotation. Probes are contributed by the builders that own
    // each connection; a memory-only deployment registers none and is always
    // ready.
    app.use(createReadinessRouter(express, {
        probes: options.probes,
        timeoutMs: options.readinessTimeoutMs,
        logger: options.logger,
    }));
    // Prometheus scrape endpoint. Same reasoning as the probes above: it has to
    // keep answering while the auth pipeline is degraded, because that is when
    // the series matter.
    app.use(options.metrics.route(express, {
        probes: options.probes,
        probeTimeoutMs: options.readinessTimeoutMs,
    }));
    // The composed auth router, which ends in core's terminal handler.
    app.use(options.router);
    // Core's terminal handler again, LAST (#293 item 8), for the host routes
    // above: Express routes an error only to handlers registered after the
    // route that threw it. See the file header.
    app.use(terminalErrorHandler(options.logger));
}
