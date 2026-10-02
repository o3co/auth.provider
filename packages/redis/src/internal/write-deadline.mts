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
 * A conditional write's write lifetime W (docs/adapter-surface.md,
 * "Conditional writes", rule 6). The adapter stamps each write with a deadline,
 * its issue time plus {@link WRITE_TIMEOUT_MS} on the app's clock; the write's
 * script refuses it at or after that deadline on the server's clock, writing
 * nothing; and the adapter stops waiting at the same timeout. A command the driver
 * queues, sends again after a reconnect, or a stalled server holds therefore
 * commits within W of its issue or writes nothing, while the app's and
 * Redis's clocks agree within {@link CLOCK_SKEW_MS}, and the server does not
 * stall inside a running script, between its clock check and its write, for
 * the whole of W.
 */

/**
 * How far past its issue a write's deadline lies, and how long the adapter
 * waits for its answer. It matches the 1 000 ms `commandTimeout` the README
 * asks of the connection.
 */
export const WRITE_TIMEOUT_MS = 1_000;

/**
 * The clock skew allowed between the app, which sets a deadline, and the
 * Redis server, which judges it: the 1 s the operator runbook asks of every
 * replica's clock ("Replica clocks").
 */
export const CLOCK_SKEW_MS = 1_000;

/** W: a conditional write commits or fails within this of its issue. */
export const WRITE_LIFETIME_MS = WRITE_TIMEOUT_MS + CLOCK_SKEW_MS;

/**
 * `write` run with its deadline, {@link WRITE_TIMEOUT_MS} from now, and its
 * answer awaited no longer than that: past it, the wait ends in
 * `unanswered()`, whose outcome is unknown (the write may have committed, or
 * may still commit within W).
 */
export async function withWriteDeadline<T>(
	write: (deadlineMs: number) => Promise<T>,
	unanswered: () => Error,
): Promise<T> {
	const deadlineMs = Date.now() + WRITE_TIMEOUT_MS;
	let timer: ReturnType<typeof setTimeout> | undefined;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(() => reject(unanswered()), WRITE_TIMEOUT_MS);
		timer.unref?.();
	});
	try {
		return await Promise.race([write(deadlineMs), timeout]);
	} finally {
		clearTimeout(timer);
	}
}
