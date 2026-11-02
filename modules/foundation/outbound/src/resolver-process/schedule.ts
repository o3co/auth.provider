export interface ScheduleLimits {
	readonly windowMs: number;
	readonly faultRestarts: number;
	readonly abandonRestarts: number;
	readonly backoffMs: number;
	readonly maxBackoffMs: number;
}

/** When a pool starts its helper again, by the card's backoff and windows, as state alone: it starts nothing and sets no timer. */
export function restartSchedule(now: () => number, limits: ScheduleLimits) {
	const faults: number[] = [];
	const abandons: number[] = [];
	let backoff = limits.backoffMs;
	let recovering = false;
	let refusingUntil = 0;

	const recent = (times: number[]) => {
		const since = now() - limits.windowMs;
		while (times.length > 0 && (times[0] as number) <= since) times.shift();
		return times.length;
	};

	return {
		/** A helper's end after a fault: the backoff, or refusing past the window's fault restarts. */
		faulted():
			| { readonly delayMs: number }
			| { readonly refusingUntil: number; readonly restarts: number } {
			faults.push(now());
			recovering = true;
			if (recent(faults) > limits.faultRestarts) {
				refusingUntil = (faults[0] as number) + limits.windowMs;
				return { refusingUntil, restarts: recent(faults) };
			}
			const delayMs = backoff;
			backoff = Math.min(backoff * 2, limits.maxBackoffMs);
			return { delayMs };
		},
		abandoned(): void {
			abandons.push(now());
		},
		abandonable(): true | { readonly recheckAt: number } {
			if (recent(abandons) >= limits.abandonRestarts) {
				return { recheckAt: (abandons[0] as number) + limits.windowMs };
			}
			return true;
		},
		recovered(): boolean {
			if (!recovering) return false;
			recovering = false;
			backoff = limits.backoffMs;
			return true;
		},
		refusing(): boolean {
			return now() < refusingUntil;
		},
	};
}
