import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type ConnectionOptions,
	connect,
	createServer,
	type Server,
	type TlsOptions as ServerOptions,
} from "node:tls";
import { promisify } from "node:util";
import type { TlsOptions } from "./contract.ts";
import tlsOptionsModule from "./module.ts";
import { optionsOf } from "./options.ts";
import { section } from "./section.ts";

/** For tests: the module, its section left to its defaults, to compose wherever a module takes `tlsOptions`. */
export const tlsOptionsForTests = tlsOptionsModule;

/**
 * For tests: the options a section as written gives, read through its schema (refusing what boot
 * would) and made as the module makes them, for a function taking them directly.
 */
export const tlsOptionsFor = (written: unknown): TlsOptions => optionsOf(section.parse(written));

/** For tests: the options the section's defaults give. */
export const testTlsOptions = tlsOptionsFor({});

/** A key and its self-signed certificate for localhost, the certificate its own authority. */
interface Certificate {
	readonly key: string;
	readonly cert: string;
}

/** The certificates the peers show, made by openssl when first asked, never kept on disk. */
interface Certificates {
	readonly ecdsa: Certificate;
	/** A peer offering the RSA key exchange needs an RSA key. */
	readonly rsa: Certificate;
}

const newKey = {
	ecdsa: ["ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-pkeyopt", "ec_param_enc:named_curve"],
	rsa: ["rsa:2048"],
} as const;

async function selfSigned(dir: string, kind: keyof typeof newKey): Promise<Certificate> {
	const [key, cert] = [join(dir, `${kind}-key.pem`), join(dir, `${kind}-cert.pem`)];
	await promisify(execFile)(
		"openssl",
		[
			"req",
			"-x509",
			"-newkey",
			...newKey[kind],
			"-nodes",
			"-days",
			"2",
			"-subj",
			"/CN=localhost",
			"-addext",
			"subjectAltName=DNS:localhost",
			"-keyout",
			key,
			"-out",
			cert,
		],
		{ timeout: 30_000, killSignal: "SIGKILL" },
	);
	return { key: await readFile(key, "utf8"), cert: await readFile(cert, "utf8") };
}

let made: Promise<Certificates> | undefined;

/** The peers' certificates, made once for the process. */
function certificates(): Promise<Certificates> {
	made ??= (async () => {
		const dir = await mkdtemp(join(tmpdir(), "tls-options-"));
		try {
			return { ecdsa: await selfSigned(dir, "ecdsa"), rsa: await selfSigned(dir, "rsa") };
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	})();
	return made;
}

/**
 * For tests: TLS peers that each offer one thing alone, for a client's options to be held against:
 * an old version, static RSA key exchange, CBC suites, or what BCP 195 (RFC 9325) takes, ECDHE with
 * AEAD on TLS 1.2 and TLS 1.3. Their certificates are made by openssl, which must be on the path.
 */
export type Offer = "tls1.1" | "static-rsa" | "cbc" | "ecdhe-aead" | "tls1.3";

/** What each peer offers, its versions and suites, and the certificate it shows. */
const offers: Record<
	Offer,
	{ readonly server: ServerOptions; readonly shows: keyof Certificates }
> = {
	// Below TLS 1.2 OpenSSL needs its security level lowered to offer anything.
	"tls1.1": {
		server: {
			minVersion: "TLSv1.1",
			maxVersion: "TLSv1.1",
			ciphers: "ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0",
		},
		shows: "ecdsa",
	},
	"static-rsa": {
		server: { minVersion: "TLSv1.2", maxVersion: "TLSv1.2", ciphers: "AES128-GCM-SHA256" },
		shows: "rsa",
	},
	cbc: {
		server: {
			minVersion: "TLSv1.2",
			maxVersion: "TLSv1.2",
			ciphers: "ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA",
		},
		shows: "ecdsa",
	},
	"ecdhe-aead": {
		server: {
			minVersion: "TLSv1.2",
			maxVersion: "TLSv1.2",
			ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256",
		},
		shows: "ecdsa",
	},
	"tls1.3": { server: { minVersion: "TLSv1.3" }, shows: "ecdsa" },
};

/** What a handshake came to: the version and suite agreed, or refused, with the code each side's error gave. */
export type Handshake =
	| { readonly kind: "agreed"; readonly protocol: string | null; readonly cipher: string }
	| { readonly kind: "refused"; readonly code: string; readonly peerCode: string };

/**
 * The options of a peer offering `offer` alone, key and certificate included, and the authority to
 * trust it by, its name `localhost`: for a server of the caller's own (HTTP, SMTP, Redis) to answer
 * past the handshake.
 */
export async function peerOptions(offer: Offer): Promise<{ server: ServerOptions; ca: string }> {
	const certificate = (await certificates())[offers[offer].shows];
	return { server: { ...offers[offer].server, ...certificate }, ca: certificate.cert };
}

/**
 * A peer offering `offer` on localhost, ending each connection after its handshake, until closed;
 * `refused` answers the code of the first handshake it refused.
 */
async function peer(
	server: ServerOptions,
): Promise<{ port: number; refused: Promise<string>; close(): Promise<void> }> {
	const listening: Server = createServer(server, (socket) => socket.end());
	const refused = new Promise<string>((answer) => {
		listening.once("tlsClientError", (error: NodeJS.ErrnoException) =>
			answer(error.code ?? error.message),
		);
	});
	await new Promise<void>((resolve) => listening.listen(0, "127.0.0.1", resolve));
	const address = listening.address();
	const port = typeof address === "object" && address ? address.port : 0;
	return { port, refused, close: () => new Promise((resolve) => listening.close(() => resolve())) };
}

/** The handshake a client with `options` comes to with a peer offering `offer` alone, trusting its certificate. */
export async function handshakeWith(options: ConnectionOptions, offer: Offer): Promise<Handshake> {
	const { server, ca } = await peerOptions(offer);
	const p = await peer(server);
	try {
		return await new Promise<Handshake>((resolve) => {
			const socket = connect({
				...options,
				host: "127.0.0.1",
				port: p.port,
				servername: "localhost",
				ca,
			});
			socket.once("secureConnect", () => {
				resolve({
					kind: "agreed",
					protocol: socket.getProtocol(),
					cipher: socket.getCipher().name,
				});
				socket.destroy();
			});
			socket.once("error", async (error: NodeJS.ErrnoException) => {
				// The peer's own word, unless it never refused one: then this was no refused handshake.
				const peerCode = await Promise.race([
					p.refused,
					new Promise<string>((none) => setTimeout(() => none("none"), 2000)),
				]);
				resolve({ kind: "refused", code: error.code ?? error.message, peerCode });
			});
		});
	} finally {
		await p.close();
	}
}
