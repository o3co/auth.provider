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
 * suite's names `localhost`, not the host it is reached by, so its name is no check.
 */
export function pinnedTo(pem: string) {
	const pinned = new X509Certificate(pem).fingerprint256;
	return (_host: string, presented: { readonly fingerprint256: string }) =>
		presented.fingerprint256 === pinned
			? undefined
			: new Error("the suite answered with another certificate than the one first read");
}

/** A JSON GET at the suite, trusting the certificate it was first read with alone. */
export async function getJson(url: string, ca: string): Promise<{ status: number; body: unknown }> {
	const { request } = await import("node:https");
	const checkServerIdentity = pinnedTo(ca);
	return new Promise((resolve, reject) => {
		const req = request(url, { ca, checkServerIdentity, timeout: 30_000 }, (res) => {
			// An answer cut off midway is refused, never left pending.
			res.on("error", reject);
			res.on("aborted", () => reject(new Error(`the suite cut its answer to ${url} off`)));
			let text = "";
			res.on("data", (chunk) => {
				text += chunk;
			});
			res.on("end", () => {
				let body: unknown = text;
				try {
					body = JSON.parse(text);
				} catch {}
				resolve({ status: res.statusCode ?? 0, body });
			});
		});
		req.on("timeout", () => req.destroy(new Error(`the suite did not answer ${url}`)));
		req.on("error", reject);
		req.end();
	});
}
