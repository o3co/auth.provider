import { execFile } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import {
	type IncomingHttpHeaders,
	type IncomingMessage,
	type OutgoingHttpHeaders,
	request,
	type ServerResponse,
} from "node:http";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import type { TLSSocket } from "node:tls";
import { promisify } from "node:util";

/** A key and a self-signed certificate naming `host` and loopback, written in `dir` by openssl. */
export async function selfSigned(
	host: string,
	dir: string,
): Promise<{ key: string; cert: string }> {
	await mkdir(dir, { recursive: true });
	const key = join(dir, "key.pem");
	const cert = join(dir, "cert.pem");
	await promisify(execFile)("openssl", [
		"req",
		"-x509",
		"-newkey",
		"ec",
		"-pkeyopt",
		"ec_paramgen_curve:P-256",
		// LibreSSL writes explicit curve parameters otherwise, which Java's TLS refuses.
		"-pkeyopt",
		"ec_param_enc:named_curve",
		"-nodes",
		"-days",
		"2",
		"-subj",
		`/CN=${host}`,
		"-addext",
		`subjectAltName=DNS:${host},DNS:localhost,IP:127.0.0.1`,
		"-keyout",
		key,
		"-out",
		cert,
	]);
	return { key: await readFile(key, "utf8"), cert: await readFile(cert, "utf8") };
}

/** A request at the front, its URL on the front's public origin. */
export interface FrontRequest {
	readonly method: string;
	readonly url: URL;
	readonly headers: IncomingHttpHeaders;
	readonly body: Buffer;
	/** The address it came from. */
	readonly address: string;
}

/** An answer the front gives itself. */
export interface FrontAnswer {
	readonly status: number;
	readonly headers?: OutgoingHttpHeaders;
	readonly body?: string | Buffer;
}

export interface FrontOptions {
	/** Where the app listens: read for each request, so the front can start before the app. */
	readonly upstream: () => string;
	/** The host the front's clients name it by; its certificate names it. */
	readonly publicHost: string;
	/** The address the front listens on. */
	readonly listen: string;
	readonly tls: { readonly key: string; readonly cert: string };
	/** Asks each client for a certificate, and forwards it URL-encoded in this header. */
	readonly clientCertificate?: { readonly header: string };
	/** Answers a request at the front; one it leaves goes on to the app. */
	handle?(request: FrontRequest): FrontAnswer | undefined | Promise<FrontAnswer | undefined>;
	/** The URL and body a request goes on to the app with. */
	rewrite?(request: FrontRequest): { readonly url: URL; readonly body: Buffer };
	/** Told each answer the app gives, with the request it answers. */
	answered?(
		request: FrontRequest,
		answer: { readonly status: number; readonly headers: IncomingHttpHeaders },
	): void;
}

/** The front as it runs: the origin its clients reach the app at. */
export interface Front {
	readonly origin: string;
	stop(): Promise<void>;
}

/** Headers never passed on: a connection's own, and what only the front says. */
const hopByHop = [
	"connection",
	"keep-alive",
	"transfer-encoding",
	"upgrade",
	"host",
	"content-length",
];
const frontsOwn = ["forwarded", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"];

const bodyOf = (req: IncomingMessage) =>
	new Promise<Buffer>((resolve, reject) => {
		const chunks: Buffer[] = [];
		req.on("data", (chunk: Buffer) => chunks.push(chunk));
		req.on("end", () => resolve(Buffer.concat(chunks)));
		req.on("error", reject);
	});

const pemOf = (der: Buffer) =>
	`-----BEGIN CERTIFICATE-----\n${der
		.toString("base64")
		.match(/.{1,64}/g)
		?.join("\n")}\n-----END CERTIFICATE-----`;

const answer = (res: ServerResponse, given: FrontAnswer) => {
	res.writeHead(given.status, given.headers ?? {});
	res.end(given.body ?? "");
};

/**
 * Starts an https front of the app at `upstream()`, as a deployment's proxy is: it ends TLS and
 * tells the app the scheme and the sender's address alone, and the certificate a client presented
 * where asked. Its public origin is its host and the port it took, known before the app starts.
 */
export async function startFront(options: FrontOptions): Promise<Front> {
	let origin = "";
	const certificateHeader = options.clientCertificate?.header.toLowerCase();
	const dropped = new Set([
		...hopByHop,
		...frontsOwn,
		...(certificateHeader === undefined ? [] : [certificateHeader]),
	]);
	const pass = async (req: IncomingMessage, res: ServerResponse) => {
		const received: FrontRequest = {
			method: req.method ?? "GET",
			url: new URL(req.url ?? "/", origin),
			headers: req.headers,
			body: await bodyOf(req),
			address: req.socket.remoteAddress ?? "",
		};
		const handled = await options.handle?.(received);
		if (handled !== undefined) return answer(res, handled);
		const { url, body } = options.rewrite?.(received) ?? received;
		const headers: OutgoingHttpHeaders = Object.fromEntries(
			Object.entries(req.headers).filter(([name]) => !dropped.has(name)),
		);
		headers["x-forwarded-proto"] = "https";
		headers["x-forwarded-for"] = received.address;
		if (body.length > 0 || req.headers["content-length"] !== undefined)
			headers["content-length"] = String(body.length);
		const presented = (req.socket as TLSSocket).getPeerCertificate?.();
		if (certificateHeader !== undefined && presented?.raw !== undefined)
			headers[certificateHeader] = encodeURIComponent(pemOf(presented.raw));
		const upstream = new URL(options.upstream());
		const sent = request(
			{
				host: upstream.hostname,
				port: upstream.port,
				method: received.method,
				path: `${url.pathname}${url.search}`,
				headers,
			},
			(app) => {
				options.answered?.(received, { status: app.statusCode ?? 502, headers: app.headers });
				const back = Object.fromEntries(
					Object.entries(app.headers).filter(
						([name]) => !hopByHop.includes(name) || name === "content-length",
					),
				);
				res.writeHead(app.statusCode ?? 502, back);
				app.pipe(res);
			},
		);
		sent.on("error", () => answer(res, { status: 502 }));
		sent.end(body);
	};
	const server = createServer(
		{
			key: options.tls.key,
			cert: options.tls.cert,
			// The app judges a certificate; the front only carries the one presented.
			...(certificateHeader === undefined ? {} : { requestCert: true, rejectUnauthorized: false }),
		},
		(req, res) => {
			pass(req, res).catch(() => {
				if (!res.headersSent) answer(res, { status: 502 });
				else res.end();
			});
		},
	);
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, options.listen, () => resolve());
	});
	origin = `https://${options.publicHost}:${(server.address() as AddressInfo).port}`;
	return {
		origin,
		stop: () =>
			new Promise<void>((resolve) => {
				server.closeAllConnections();
				server.close(() => resolve());
			}),
	};
}
