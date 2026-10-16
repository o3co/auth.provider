import type { HttpRequest } from "@mod/http";
import { readSecretHash, type SecretChecker, type SecretHash } from "@mod/secret-hash";
import { z } from "zod";
import type { AuthMethod, Client, ClientRecord, Section } from "./contract.ts";

const secretFields = z.strictObject({
	/** A bcrypt or scrypt hash of the secret. */
	hash: z.string().optional(),
});

/** The section's hash as secret-hash reads it; undefined when it holds none or one that does not read. */
const hashIn = ({ hash }: z.output<typeof secretFields>) =>
	hash === undefined ? undefined : readSecretHash(hash);

export const secretSection: Section<z.output<typeof secretFields>> = {
	name: "client-secret",
	schema: secretFields,
	// The value is never put in the reason.
	checkAtBoot: (fields) =>
		fields.hash !== undefined && hashIn(fields) === undefined
			? "the secret is no bcrypt or scrypt hash (a plain-text secret is refused)"
			: undefined,
};

/** The methods whose clients must hold a secret's hash. */
export const secretMethods: readonly string[] = ["client_secret_basic", "client_secret_post"];

/** The hashes registered clients hold, for the checker's decoys, read from the settings: the clients are built after the methods. */
export function hashesOf(registered: readonly ClientRecord[]): SecretHash[] {
	return registered.flatMap((r) => {
		const read = secretFields.safeParse(r.sections[secretSection.name] ?? {});
		const hash = read.success ? hashIn(read.data) : undefined;
		return hash ? [hash] : [];
	});
}

/** Undoes the form encoding RFC 6749 §2.3.1 puts on a Basic id and secret; undefined if it does not decode. */
function formDecoded(s: string): string | undefined {
	try {
		return decodeURIComponent(s.replaceAll("+", " "));
	} catch {
		return undefined;
	}
}

/** Throws on bytes that are not UTF-8; `ignoreBOM: true` keeps a leading BOM in the text, never drops it. */
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function utf8(bytes: Uint8Array): string | undefined {
	try {
		return strictUtf8.decode(bytes);
	} catch {
		return undefined;
	}
}

/** Whether the body sends this name, as a string or of another type. */
const sends = ({ fields, mistyped }: HttpRequest, name: string) =>
	fields.has(name) || mistyped?.has(name) === true;

const usesBasic = (request: HttpRequest) =>
	/^Basic(\s|$)/i.test(request.headers.get("authorization") ?? "");

/** The id and secret of a Basic header; undefined when it does not decode to a non-empty one of each. */
function basic(request: HttpRequest): { id: string; secret: string } | undefined {
	const header = request.headers.get("authorization");
	const match = header?.match(/^Basic +([A-Za-z0-9+/=]+)$/i);
	if (!match?.[1]) return undefined;
	// Only canonical base64 of UTF-8: Node's decoders skip stray characters and replace bad bytes.
	const bytes = Buffer.from(match[1], "base64");
	if (bytes.toString("base64") !== match[1]) return undefined;
	const decoded = utf8(bytes);
	if (decoded === undefined) return undefined;
	const colon = decoded.indexOf(":");
	if (colon < 0) return undefined;
	const id = formDecoded(decoded.slice(0, colon));
	const secret = formDecoded(decoded.slice(colon + 1));
	return id && secret ? { id, secret } : undefined;
}

/** Whether the secret is the client's; a client without a hash, and a hash not read, still cost the checker's work. */
function secretMatches(checker: SecretChecker, client: Client, secret: string): Promise<boolean> {
	return checker.check(hashIn(client.section(secretSection)), secret);
}

export const secretBasic = (checker: SecretChecker): AuthMethod => ({
	name: "client_secret_basic",
	challenge: 'Basic realm="client"',
	// A Basic header that does not decode still uses this method, and is refused as malformed.
	claimed: (request) => (usesBasic(request) ? (basic(request)?.id ?? "") : undefined),
	malformed: (request) => usesBasic(request) && basic(request) === undefined,
	verify: async (request, client) => {
		const credentials = basic(request);
		if (credentials === undefined) return false;
		// A client_id in the body must name the same client, so one request never names two.
		const named =
			!sends(request, "client_id") || request.fields.single("client_id") === credentials.id;
		return named && secretMatches(checker, client, credentials.secret);
	},
});

export const secretPost = (checker: SecretChecker): AuthMethod => ({
	name: "client_secret_post",
	// A secret without one client_id beside it still uses this method, and is refused as malformed.
	claimed: (request) =>
		sends(request, "client_secret") ? (request.fields.single("client_id") ?? "") : undefined,
	malformed: (request) =>
		sends(request, "client_secret") &&
		(!request.fields.single("client_id") || request.fields.single("client_secret") === undefined),
	verify: async (request, client) => {
		const secret = request.fields.single("client_secret");
		return secret !== undefined && secretMatches(checker, client, secret);
	},
});

export const none: AuthMethod = {
	name: "none",
	// Tried only when no other method claims the request; an empty client_id is no credentials.
	claimed: (request) => request.fields.single("client_id") || undefined,
	// A client_id sent twice, or not as a string, names no one client.
	malformed: (request) =>
		sends(request, "client_id") && request.fields.single("client_id") === undefined,
	verify: async (_request, client) => client.kind === "public",
};
