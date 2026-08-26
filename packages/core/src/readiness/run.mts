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

import type { ProbeResult, ReadinessProbe, ReadinessReport } from "./types.mjs";

export interface RunReadinessOptions {
	/**
	 * Per-probe deadline. A probe that has not settled by then is reported as
	 * failed. This has to be shorter than whatever scrape interval the
	 * orchestrator uses, or an unready pod reads as a slow one.
	 */
	readonly timeoutMs: number;
	/**
	 * Caller-owned map of checks that have not settled yet, keyed by probe name.
	 *
	 * Abandoning a check at the deadline does not cancel it. Against a
	 * partitioned Redis the driver holds the `PING` in its offline queue until
	 * reconnect, so without this every scrape adds another pending command —
	 * unbounded during a long outage, and released as a burst on recovery. With
	 * it, a probe whose previous check is still running is *joined* rather than
	 * re-issued: one in-flight command per dependency no matter how often the
	 * endpoint is scraped. Each caller still applies its own deadline, so a
	 * joining request does not inherit how long the shared check has already
	 * been waiting.
	 *
	 * Pass the same map across calls (the readiness router holds one for its
	 * lifetime). Omit it and every call issues its own check.
	 */
	readonly inFlight?: Map<string, Promise<unknown>>;
}

function describeError(err: unknown): string {
	if (err instanceof Error) return err.message;
	return String(err);
}

/**
 * Start `probe.check()`, or join the one already running for this probe.
 *
 * The entry is removed as soon as the check settles, so a later scrape starts
 * a fresh one rather than reading a stale verdict. The `catch` on the stored
 * promise is what keeps a rejection from surfacing as an unhandled rejection
 * once every waiter has already timed out and stopped listening.
 */
function startOrJoin(
	probe: ReadinessProbe,
	inFlight?: Map<string, Promise<unknown>>,
): Promise<unknown> {
	if (!inFlight) return probe.check();

	const existing = inFlight.get(probe.name);
	if (existing) return existing;

	const started = probe.check();
	inFlight.set(probe.name, started);
	void started
		.catch(() => {})
		.finally(() => {
			// Only clear our own entry: a slower predecessor settling later must
			// not evict the check a subsequent scrape started.
			if (inFlight.get(probe.name) === started) inFlight.delete(probe.name);
		});
	return started;
}

async function runOne(
	probe: ReadinessProbe,
	timeoutMs: number,
	inFlight?: Map<string, Promise<unknown>>,
): Promise<ProbeResult> {
	const started = Date.now();
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		await Promise.race([
			startOrJoin(probe, inFlight),
			new Promise((_resolve, reject) => {
				timer = setTimeout(
					() => reject(new Error(`probe timed out after ${timeoutMs}ms`)),
					timeoutMs,
				);
			}),
		]);
		return { name: probe.name, ok: true, durationMs: Date.now() - started };
	} catch (err) {
		return {
			name: probe.name,
			ok: false,
			durationMs: Date.now() - started,
			error: describeError(err),
		};
	} finally {
		// Always clear: on the success path the timer is still armed, and an
		// endpoint scraped every few seconds would otherwise accumulate one
		// pending timer per scrape and hold the event loop open at shutdown.
		if (timer !== undefined) clearTimeout(timer);
	}
}

/**
 * Run every probe concurrently under a shared per-probe deadline.
 *
 * A dependency being down must not hide the state of the others, so no probe
 * short-circuits the rest: each one is reported individually and `ready` is
 * simply the conjunction. A deployment that registered no probes is ready —
 * absence of a wired dependency is not evidence of a broken one.
 */
export async function runReadinessProbes(
	probes: readonly ReadinessProbe[],
	options: RunReadinessOptions,
): Promise<ReadinessReport> {
	const checks = await Promise.all(
		probes.map((probe) => runOne(probe, options.timeoutMs, options.inFlight)),
	);
	return { ready: checks.every((c) => c.ok), checks };
}
