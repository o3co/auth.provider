import { createServer, request } from "node:http";

/** A request an instance was sent, by method and path, when (the base's monotonic clock, ms). */
export interface Traced {
	readonly method: string;
	readonly path: string;
	readonly at: number;
}

/**
 * A plain HTTP proxy in front of one instance that records each request sent to it, so a scene can
 * tell which instance was asked what. The app reads its public origin from configuration only, so
 * standing in front of it changes nothing it answers.
 */
export async function startTrace(target: string) {
	let to = new URL(target);
	const traced: Traced[] = [];
	const server = createServer((req, res) => {
		traced.push({ method: req.method ?? "", path: req.url ?? "", at: performance.now() });
		const forward = request(
			{
				host: to.hostname,
				port: to.port,
				method: req.method,
				path: req.url,
				headers: req.headers,
			},
			(answer) => {
				res.writeHead(answer.statusCode ?? 502, answer.rawHeaders);
				answer.pipe(res);
			},
		);
		forward.on("error", () => {
			if (!res.headersSent) res.writeHead(502);
			res.end();
		});
		req.pipe(forward);
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	const port = typeof address === "object" && address ? address.port : 0;
	return {
		url: `http://127.0.0.1:${port}`,
		requests: (): readonly Traced[] => [...traced],
		/** Sends what comes from now on to the instance started again. */
		pointAt(base: string) {
			to = new URL(base);
		},
		stop: () =>
			new Promise<void>((resolve) => {
				server.closeAllConnections();
				server.close(() => resolve());
			}),
	};
}

export type Trace = Awaited<ReturnType<typeof startTrace>>;
