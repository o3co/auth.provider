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
import { runReadinessProbes } from "../readiness/run.mjs";
/**
 * Readiness endpoint — answers whether this replica can currently serve.
 *
 * Distinct from `/_healthcheck`, which is liveness: a static 200 proving the
 * process is up and its event loop is turning. Liveness answering 200 during a
 * Redis partition is correct — restarting the process would not reconnect
 * Redis any faster — but it must not be what a load balancer uses to decide
 * whether to keep sending logins here. That is this route's job.
 *
 * Mount it on the host app ahead of the composed auth router so it stays
 * reachable while the auth pipeline is degraded.
 */
export function createRouter(express, opts) {
    const router = express.Router();
    const includeErrorDetail = opts.includeErrorDetail === true;
    // Held for the router's lifetime so concurrent and repeated scrapes join one
    // in-flight check per dependency instead of queueing a command each. During
    // a partition the driver never answers, and this endpoint is reachable
    // without credentials.
    const inFlight = new Map();
    router.get(opts.path ?? "/readyz", async (_req, res) => {
        const report = await runReadinessProbes(opts.probes, {
            timeoutMs: opts.timeoutMs,
            inFlight,
        });
        // An orchestrator polls this; a cached "ready" would outlive the outage
        // it describes.
        res.setHeader("Cache-Control", "no-store");
        if (!report.ready) {
            // The log keeps the full detail the body drops — the operator reading
            // it is already inside the deployment.
            opts.logger?.warn({ checks: report.checks.filter((c) => !c.ok) }, "readiness_probe_failed");
        }
        res.status(report.ready ? 200 : 503).json({
            status: report.ready ? "ready" : "unready",
            checks: report.checks.map(({ name, ok, durationMs, error }) => ({
                name,
                ok,
                durationMs,
                ...(includeErrorDetail && error !== undefined ? { error } : {}),
            })),
        });
    });
    return router;
}
