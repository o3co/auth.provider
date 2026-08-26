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
}

function describeError(err: unknown): string {
	if (err instanceof Error) return err.message;
	return String(err);
}

async function runOne(probe: ReadinessProbe, timeoutMs: number): Promise<ProbeResult> {
	const started = Date.now();
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		await Promise.race([
			probe.check(),
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
	const checks = await Promise.all(probes.map((probe) => runOne(probe, options.timeoutMs)));
	return { ready: checks.every((c) => c.ok), checks };
}
