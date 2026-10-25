import { z } from "zod";

/** What a configured URL may hold beyond a scheme and a host. */
export interface UrlRules {
	/** Lower case; the value must be written `<scheme>://`. */
	readonly schemes: readonly ("https" | "http")[];
	/**
	 * "kept" (default): a path ending in `/` stays as written. "refused": refused, for identifiers
	 * compared as strings.
	 */
	readonly trailingSlash?: "kept" | "refused";
	/** Whether a query may be part of it (default true). */
	readonly query?: boolean;
	/** Whether plain `http` is taken beside the schemes, on a loopback host only (default false). */
	readonly loopbackHttp?: boolean;
	/** An origin alone: a scheme, a host and a port, with no path, not even `/`, and no query. */
	readonly origin?: true;
}

/** Why a value is not a URL these rules take; undefined when it is one. Names no part of the value. */
function refusal(value: string, rules: UrlRules): string | undefined {
	// Characters a URL parser drops or rereads, so the value would not mean what it says.
	const control = [...value].some((c) => (c.codePointAt(0) ?? 0) < 0x20 || c === "\u007f");
	if (control || /\s/.test(value)) return form("whitespace or control characters");
	if (value.includes("\\")) return form("a backslash");
	const schemes: readonly string[] = rules.loopbackHttp
		? [...rules.schemes, "http"]
		: rules.schemes;
	const scheme = schemes.find((s) => value.startsWith(`${s}://`));
	if (!scheme) {
		const cased = schemes.some((s) => value.toLowerCase().startsWith(`${s}://`));
		if (cased) return form("a scheme not in lower case");
		const starts = rules.schemes.map((s) => `${s}://`);
		const local = rules.loopbackHttp ? ["http:// on a loopback host"] : [];
		return `a URL: starting ${[...starts, ...local].join(" or ")}`;
	}
	const rest = value.slice(scheme.length + 3);
	const authority = rest.split(/[/?#]/, 1)[0] ?? "";
	if (authority === "" || !URL.canParse(value)) return "a URL: a host";
	if (authority.includes("@")) return "a URL: no userinfo";
	if (value.includes("#")) return "a URL: no fragment";
	if (rules.query === false && value.includes("?")) return "a URL: no query";
	const path = rest.slice(authority.length).split("?", 1)[0] ?? "";
	if (rules.origin && (path !== "" || value.includes("?"))) {
		return "a URL: an origin alone, with no path (not even a trailing `/`) and no query";
	}
	if (rules.trailingSlash === "refused" && path.endsWith("/")) return "a URL: no trailing /";
	const url = new URL(value);
	const kind = difference(url, authority, path, value);
	if (kind) return form(kind);
	// Decided on the parser's form only, which the value now is, so no other spelling reaches here.
	if (!rules.schemes.some((s) => s === scheme) && !isLoopbackName(url.hostname)) {
		return "a URL: http only on a loopback host";
	}
	return undefined;
}

/**
 * Whether a host is a loopback one by its name alone, never resolved: `localhost` or a name under it
 * (RFC 6761), in any case and with or without a trailing dot; an IPv4 address in 127.0.0.0/8 as the
 * URL parser writes it; or `::1` or 127.0.0.0/8 mapped into IPv6, however written. Bracketed or not.
 */
export function isLoopbackName(host: string): boolean {
	const bracketed = host.startsWith("[") && host.endsWith("]");
	const bare = bracketed ? host.slice(1, -1) : host;
	if (bare.includes(":")) {
		const written = URL.parse(`http://[${bare}]/`)?.hostname;
		return written === "[::1]" || /^\[::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}\]$/.test(written ?? "");
	}
	if (bracketed) return false;
	const lower = bare.toLowerCase();
	if (/^[0-9.]+$/.test(lower)) {
		return URL.parse(`http://${lower}/`)?.hostname === lower && /^127(\.\d{1,3}){3}$/.test(lower);
	}
	const labels = (lower.endsWith(".") ? lower.slice(0, -1) : lower).split(".");
	return labels.at(-1) === "localhost" && labels.every((label) => label !== "");
}

/**
 * Whether a URL is plain `http` on a loopback host (`isLoopbackName`), as a module's own production
 * check asks of a URL `loopbackHttp` took: such a page is the operator's machine, never a user's.
 */
export function isLoopbackHttp(url: string): boolean {
	const parsed = URL.parse(url);
	return parsed?.protocol === "http:" && isLoopbackName(parsed.hostname);
}

function form(kind: string): string {
	return `a URL as the URL parser writes it; refused for ${kind}`;
}

/**
 * How a value differs from the form the URL parser writes it in (an empty path may stay empty);
 * undefined when it does not. Compared as written, so only that form is taken.
 */
function difference(url: URL, authority: string, path: string, value: string): string | undefined {
	// The host ends at the port's `:`, past an IPv6 address's brackets.
	const colon = authority.indexOf(":", authority.startsWith("[") ? authority.indexOf("]") : 0);
	const host = colon < 0 ? authority : authority.slice(0, colon);
	if (host !== url.hostname) {
		if (host.toLowerCase() === url.hostname) return "host case";
		if (/[^\x20-\x7e]/.test(host)) return "invisible or mapped characters";
		if (host.includes("%")) return "percent-encoding in the host";
		if (/^(\d+\.){3}\d+$|^\[/.test(url.hostname)) return "an IP address not in its shortest form";
		return "a difference from the parser's form";
	}
	const port = colon < 0 ? undefined : authority.slice(colon + 1);
	if (port === "") return "an empty port";
	if (port !== undefined && port !== url.port) {
		return url.port === "" ? "a default port written" : "a leading zero in the port";
	}
	// A `.` or `..` segment, also percent-encoded; the parser resolves it.
	const segments = path.split("/");
	const dot = segments.findIndex((s) => /^(\.|%2e){1,2}$/i.test(s));
	if (dot >= 0) return dot === segments.length - 1 ? "the path's ending" : "dot segments";
	const written = path === "" ? url.origin + url.href.slice(url.origin.length + 1) : url.href;
	if (written === value) return undefined;
	if (percentEncoded(value, written)) return "characters the parser percent-encodes";
	return "a difference from the parser's form";
}

/** Whether `written` is `value` with some characters percent-encoded as UTF-8, and nothing else. */
function percentEncoded(value: string, written: string): boolean {
	let at = 0;
	for (const c of value) {
		if (written.startsWith(c, at)) {
			at += c.length;
			continue;
		}
		const bytes = [...new TextEncoder().encode(c)];
		const encoded = bytes.map((b) => `%${b.toString(16).toUpperCase().padStart(2, "0")}`).join("");
		if (!written.startsWith(encoded, at)) return false;
		at += encoded.length;
	}
	return at === written.length;
}

/**
 * A configured URL: one of the schemes, a host, no userinfo, no fragment, no whitespace or control
 * characters, in the form the URL parser writes it; kept exactly as written.
 */
const configured = z.string().brand<"ConfiguredUrl">();
/** A URL url-setting read from an operator's configuration; nothing else makes one, so a caller holding one holds the operator's URL. */
export type ConfiguredUrl = z.output<typeof configured>;

/**
 * A path or query with what RFC 3986 holds equivalent spelled one way: an unreserved character
 * encoded is the character, and the hex of any other encoding upper case (§6.2.2.1, §6.2.2.2).
 */
const equivalent = (part: string) =>
	part.replace(/%([0-9A-Fa-f]{2})/g, (_, hex: string) => {
		const char = String.fromCharCode(Number.parseInt(hex, 16));
		return /[A-Za-z0-9\-._~]/.test(char) ? char : `%${hex.toUpperCase()}`;
	});

/**
 * Whether two URLs of an operator's configuration name one target: one origin, and a path and a
 * query RFC 3986 holds equivalent (§6.2.2), whatever their spelling.
 */
export function sameTarget(a: ConfiguredUrl, b: ConfiguredUrl): boolean {
	const [x, y] = [new URL(a), new URL(b)];
	return (
		x.origin === y.origin &&
		equivalent(x.pathname) === equivalent(y.pathname) &&
		equivalent(x.search) === equivalent(y.search)
	);
}

export function urlSetting(rules: UrlRules) {
	return configured.superRefine((value, context) => {
		const reason = refusal(value, rules);
		if (reason) context.addIssue({ code: "custom", message: reason });
	});
}

/**
 * A section's check of the URLs it sends to, as `superRefine` takes it: once every URL of `urls`
 * parses, `explain` is asked of each URL of `sent` with its hosts, and the configured URL it is sent
 * for where the key names one, and what it answers is put at that key. While one is no URL nothing is asked: that is its own key's refusal, and zod may run a
 * section's refinement past a field it refused. What a refusal says is `explain`'s alone.
 */
export function urlsChecked<S>(
	explain: (
		url: string,
		hosts: readonly string[],
		internal: ConfiguredUrl | undefined,
	) => string | undefined,
	parts: {
		readonly urls: (section: S) => readonly (string | undefined)[];
		readonly sent: (section: S) => Readonly<
			Record<
				string,
				{
					readonly url?: string | undefined;
					readonly hosts: readonly string[];
					readonly internal?: ConfiguredUrl | undefined;
				}
			>
		>;
	},
): (section: S, context: z.RefinementCtx) => void {
	return (section, context) => {
		if (!parts.urls(section).every((url) => url === undefined || URL.canParse(url))) return;
		for (const [key, { url, hosts, internal }] of Object.entries(parts.sent(section))) {
			const refused = url === undefined ? undefined : explain(url, hosts, internal);
			if (refused !== undefined)
				context.addIssue({ code: "custom", path: [key], message: refused });
		}
	};
}
