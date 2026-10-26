import type { IncomingHttpHeaders } from "node:http";

/** One request the browser made, and what it was answered. */
export interface Hop {
	readonly method: string;
	readonly url: string;
	readonly status: number;
	readonly location?: string;
}

/** The answer the browser stopped at, and the requests that led to it. */
export interface Landing {
	readonly url: string;
	readonly status: number;
	readonly headers: IncomingHttpHeaders;
	readonly body: string;
	readonly hops: readonly Hop[];
}

/** How the browser goes: where it stops, and how long each request may take. */
export interface Going {
	/** Whether to follow a redirect to this URL; it stops at the answer that sent it there otherwise. */
	readonly follow: (url: URL) => boolean;
	readonly withinMs?: number;
	readonly signal?: AbortSignal;
}

const mostHops = 10;

/** A cookie's name and value from a `Set-Cookie` line, and whether it asks to be removed. */
function cookieOf(line: string): { name: string; value: string; gone: boolean } | undefined {
	const [pair = "", ...attributes] = line.split(";");
	const at = pair.indexOf("=");
	if (at <= 0) return undefined;
	const name = pair.slice(0, at).trim();
	const value = pair.slice(at + 1).trim();
	const gone = attributes.some((a) => {
		const [key = "", given = ""] = a.split("=").map((s) => s.trim());
		if (key.toLowerCase() === "max-age") return Number(given) <= 0;
		if (key.toLowerCase() === "expires") return Date.parse(given) <= Date.now();
		return false;
	});
	return { name, value, gone };
}

/**
 * A browser for a harness: it trusts each origin's own certificate alone, follows redirects among
 * those origins, and keeps each host's cookies, as the suite's own browser would for a person.
 */
export function browser(trusted: Readonly<Record<string, string>>) {
	const jars = new Map<string, Map<string, string>>();
	const jarOf = (host: string) => {
		const jar = jars.get(host) ?? new Map<string, string>();
		jars.set(host, jar);
		return jar;
	};

	async function once(
		method: string,
		url: URL,
		body: string | undefined,
		signal: AbortSignal,
	): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
		const ca = trusted[url.origin];
		if (ca === undefined) throw new Error(`the browser trusts no certificate for ${url.origin}`);
		const { request } = await import("node:https");
		signal.throwIfAborted();
		const cookie = [...jarOf(url.host)].map(([n, v]) => `${n}=${v}`).join("; ");
		return new Promise((resolve, reject) => {
			const req = request(
				url,
				{
					method,
					ca,
					headers: {
						...(cookie ? { cookie } : {}),
						...(body === undefined ? {} : { "content-type": "application/x-www-form-urlencoded" }),
					},
				},
				(res) => {
					res.on("error", reject);
					res.on("aborted", () => reject(new Error(`${url.origin} cut its answer off`)));
					let text = "";
					res.on("data", (chunk) => {
						text += chunk;
					});
					res.on("end", () => {
						signal.removeEventListener("abort", abort);
						for (const line of res.headers["set-cookie"] ?? []) {
							const c = cookieOf(line);
							if (c === undefined) continue;
							if (c.gone) jarOf(url.host).delete(c.name);
							else jarOf(url.host).set(c.name, c.value);
						}
						resolve({ status: res.statusCode ?? 0, headers: res.headers, body: text });
					});
				},
			);
			const abort = () => {
				const error = new Error(`${url.origin} did not answer ${url.pathname} in time`, {
					cause: signal.reason,
				});
				req.destroy(error);
				reject(error);
			};
			signal.addEventListener("abort", abort, { once: true });
			req.on("error", (error) => {
				signal.removeEventListener("abort", abort);
				reject(error);
			});
			req.end(body);
		});
	}

	return {
		/**
		 * Visits `start`, following each redirect `going.follow` takes, as a GET; stops at the
		 * first answer that is no redirect, or whose redirect it does not take.
		 */
		async visit(start: string, going: Going, body?: string): Promise<Landing> {
			const signal = AbortSignal.any([
				AbortSignal.timeout(going.withinMs ?? 30_000),
				...(going.signal ? [going.signal] : []),
			]);
			const hops: Hop[] = [];
			let url = new URL(start);
			let method = body === undefined ? "GET" : "POST";
			let sent = body;
			for (;;) {
				const answer = await once(method, url, sent, signal);
				const raw = answer.headers.location;
				const next =
					answer.status >= 300 && answer.status < 400 && raw ? new URL(raw, url) : undefined;
				hops.push({
					method,
					url: url.href,
					status: answer.status,
					...(next ? { location: next.href } : {}),
				});
				if (next === undefined || !going.follow(next)) {
					return { url: url.href, ...answer, hops };
				}
				if (hops.length >= mostHops) {
					throw new Error(`more than ${mostHops} redirects from ${start}`);
				}
				url = next;
				method = "GET";
				sent = undefined;
			}
		},
		/** The cookies kept for a host, by name. */
		cookies(host: string): ReadonlyMap<string, string> {
			return new Map(jarOf(host));
		},
	};
}

export type Browser = ReturnType<typeof browser>;
