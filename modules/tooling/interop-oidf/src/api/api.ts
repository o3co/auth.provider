import { X509Certificate } from "node:crypto";
import { connect } from "node:tls";

/** A certificate as PEM, from its DER bytes. */
export const pemOf = (der: Buffer) =>
	`-----BEGIN CERTIFICATE-----\n${der
		.toString("base64")
		.match(/.{1,64}/g)
		?.join("\n")}\n-----END CERTIFICATE-----\n`;

/** Asks the suite's nginx for its certificate, without trusting it yet: the one to trust from now on. */
export async function certificateAt(
	at: { readonly host: string; readonly port: number } = { host: "127.0.0.1", port: 8443 },
	withinMs = 5_000,
): Promise<string> {
	const der = await new Promise<Buffer>((resolve, reject) => {
		const socket = connect(
			{
				host: at.host,
				port: at.port,
				servername: "localhost.emobix.co.uk",
				rejectUnauthorized: false,
			},
			() => {
				const raw = socket.getPeerCertificate().raw;
				socket.end();
				resolve(raw);
			},
		);
		socket.once("error", reject);
		// A port that takes the connection and never finishes the handshake is tried again, not waited on.
		socket.setTimeout(withinMs, () =>
			socket.destroy(new Error(`no TLS handshake within ${withinMs / 1000}s`)),
		);
	});
	return pemOf(der);
}

/**
 * The check of a server's identity that takes this certificate alone, by its fingerprint: the
 * suite's names `localhost.emobix.co.uk`, not the host it is reached by, so its name is no check.
 */
export function pinnedTo(pem: string) {
	const pinned = new X509Certificate(pem).fingerprint256;
	return (_host: string, presented: { readonly fingerprint256: string }) =>
		presented.fingerprint256 === pinned
			? undefined
			: new Error("the suite answered with another certificate than the one first read");
}

/**
 * A request at the suite, `body` sent as JSON where given, trusting the certificate it was first
 * read with alone; its answer, JSON where it reads as JSON, with its status, whatever that is. The
 * whole request, its answer's body read too, is held to `withinMs` and to `signal` (the plan's
 * deadline): a socket's idle time alone would wait on an answer that trickles in forever.
 */
export async function requestJson(
	method: "GET" | "POST" | "DELETE",
	url: string,
	ca: string,
	options: {
		readonly body?: unknown;
		readonly withinMs?: number;
		readonly signal?: AbortSignal;
	} = {},
): Promise<{ status: number; body: unknown }> {
	const { request } = await import("node:https");
	const checkServerIdentity = pinnedTo(ca);
	const withinMs = options.withinMs ?? 30_000;
	const signal = AbortSignal.any([
		AbortSignal.timeout(withinMs),
		...(options.signal ? [options.signal] : []),
	]);
	signal.throwIfAborted();
	return new Promise((resolve, reject) => {
		const sent = options.body === undefined ? undefined : JSON.stringify(options.body);
		const headers = sent === undefined ? {} : { "content-type": "application/json" };
		const req = request(url, { method, headers, ca, checkServerIdentity }, (res) => {
			// An answer cut off midway is refused, never left pending.
			res.on("error", reject);
			res.on("aborted", () => reject(new Error(`the suite cut its answer to ${url} off`)));
			let text = "";
			res.on("data", (chunk) => {
				text += chunk;
			});
			res.on("end", () => {
				signal.removeEventListener("abort", abort);
				let body: unknown = text;
				try {
					body = JSON.parse(text);
				} catch {}
				resolve({ status: res.statusCode ?? 0, body });
			});
		});
		const abort = () => {
			const error = new Error(`the suite did not answer ${url} in time`, { cause: signal.reason });
			req.destroy(error);
			reject(error);
		};
		signal.addEventListener("abort", abort, { once: true });
		req.on("error", (error) => {
			signal.removeEventListener("abort", abort);
			reject(error);
		});
		req.end(sent);
	});
}

/** A JSON GET at the suite, as `requestJson` makes it. */
export const getJson = (
	url: string,
	ca: string,
	options: { readonly withinMs?: number; readonly signal?: AbortSignal } = {},
) => requestJson("GET", url, ca, options);
