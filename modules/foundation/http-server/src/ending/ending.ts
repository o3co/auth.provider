import type { IncomingMessage, ServerResponse } from "node:http";
import type { Clock } from "@mod/kernel";
import type { RequestEnd, RequestEndObserver } from "../contract.ts";

/** Tells each observer of one request's end, once, answered or closed, after the request; gives the function naming the route it reached. */
export function ending(
	observers: readonly RequestEndObserver[],
	clock: Clock,
	req: IncomingMessage,
	res: ServerResponse,
): (path: string) => void {
	const started = clock.now();
	const method = req.method ?? "GET";
	let route: string | undefined;
	// An answered request emits finish, then close; the first one ends it.
	let ended = false;
	const end = (status: RequestEnd["status"]) => {
		if (ended) return;
		ended = true;
		// A clock set back gives 0, never a negative time.
		const ms = Math.max(0, clock.now() - started);
		const told: RequestEnd = Object.freeze({ method, ...(route && { route }), status, ms });
		for (const observer of observers) {
			// After the listener; nothing above it catches, and an unhandled rejection stops the process.
			void Promise.resolve()
				.then(() => observer.ended(told))
				.catch(() => {});
		}
	};
	res.once("finish", () => end(res.statusCode));
	res.once("close", () => end(res.headersSent ? res.statusCode : "closed"));
	return (path) => {
		route = path;
	};
}
