import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

/** A request the fake received, as it came. */
export interface Received {
	readonly method: string;
	readonly path: string;
	readonly query: URLSearchParams;
	/** Lower-case names. */
	readonly headers: Readonly<Record<string, string>>;
	readonly body: string;
	/** The body as the bytes it came in. */
	readonly bytes: Uint8Array;
}

/** What the fake answers: JSON, text, bytes or nothing, with a status (200 when left out) and headers. */
export interface Scripted {
	readonly status?: number;
	readonly headers?: Readonly<Record<string, string>>;
	readonly json?: unknown;
	readonly text?: string;
	readonly bytes?: Uint8Array;
}

export interface Fake {
	/** Where it listens: plain http at loopback, without a trailing slash. */
	readonly base: string;
	readonly received: readonly Received[];
	/** Stops it; rejects when the script failed on any request, so the scene fails with it. */
	stop(): Promise<void>;
}

/**
 * A fake HTTP server for a scene's outside parties: it keeps every request and answers each as the
 * script says. It knows no party's behaviour; the area that runs it writes the script. A script
 * that fails is answered 500, and fails the scene when the fake stops.
 */
export async function fakeHttp(
	script: (received: Received, base: string) => Scripted | Promise<Scripted>,
): Promise<Fake> {
	const received: Received[] = [];
	const failed: string[] = [];
	let base = "";
	const server = createServer((req, res) => {
		const chunks: Buffer[] = [];
		req.on("data", (chunk: Buffer) => {
			chunks.push(chunk);
		});
		req.on("end", () => {
			const url = new URL(req.url ?? "/", base);
			const headers = Object.fromEntries(
				Object.entries(req.headers).map(([name, value]) => [name, String(value)]),
			);
			const bytes = Buffer.concat(chunks);
			const asked = {
				method: req.method ?? "GET",
				path: url.pathname,
				query: url.searchParams,
				headers,
				body: bytes.toString(),
				bytes: new Uint8Array(bytes),
			};
			received.push(asked);
			void new Promise<Scripted>((answered) => answered(script(asked, base)))
				.catch((error): Scripted => {
					failed.push(
						`${asked.method} ${asked.path}: ${error instanceof Error ? error.message : String(error)}`,
					);
					return { status: 500, text: "the script failed" };
				})
				.then((answer) => {
					const json = answer.json !== undefined;
					res.writeHead(answer.status ?? 200, {
						...(json ? { "content-type": "application/json" } : {}),
						...answer.headers,
					});
					res.end(json ? JSON.stringify(answer.json) : (answer.bytes ?? answer.text ?? ""));
				});
		});
	});
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
	return {
		base,
		received,
		stop: async () => {
			await new Promise<void>((done) => server.close(() => done()));
			if (failed.length > 0) throw new Error(`the fake's script failed:\n${failed.join("\n")}`);
		},
	};
}
