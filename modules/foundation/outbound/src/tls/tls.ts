import { heldToFloor, type TlsOptions } from "@mod/tls-options";

/**
 * How each TLS connection is made: the floor it holds to (`tls-options`), and the authorities a
 * destination's certificate is checked against, for a test (the platform's otherwise).
 */
export interface Tls {
	readonly floor: TlsOptions;
	readonly ca?: string;
}

/**
 * A connection's TLS options: the test's authorities, held to the floor (its own keys last, as
 * `tls-options` knows them), so nothing loosens it and nothing else rides in with it.
 */
export const tlsOf = (tls: Tls) =>
	heldToFloor(tls.floor, tls.ca === undefined ? {} : { ca: tls.ca });

/** What each refused handshake said, by the failure outbound gave for it. */
const handshakes = new WeakMap<object, string>();

/**
 * Notes, beside `failure`, what refused the handshake behind it: the TLS alert (RFC 8446 §6, its
 * number as OpenSSL tells it, the same whatever its version) or an `ERR_SSL_*` code. Callers see the
 * failure alone; a test can tell a refused handshake from a reset or a close, which notes nothing.
 */
export function noteHandshake<T extends object>(failure: T, error: unknown): T {
	const { code, message } = (error ?? {}) as { code?: unknown; message?: unknown };
	const alert =
		typeof message === "string" ? /SSL alert number (\d+)/.exec(message)?.[1] : undefined;
	if (alert !== undefined) handshakes.set(failure, `TLS alert ${alert}`);
	else if (typeof code === "string" && code.startsWith("ERR_SSL_")) handshakes.set(failure, code);
	return failure;
}

/** What refused the handshake behind a failure, if one was refused. */
export const handshakeCodeOf = (failure: unknown): string | undefined =>
	typeof failure === "object" && failure !== null ? handshakes.get(failure) : undefined;
