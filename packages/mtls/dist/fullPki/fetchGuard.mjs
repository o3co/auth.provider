/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * The one form both sides of the allowlist comparison are reduced to:
 * lower-case, and for an IPv6 literal bracket-less in the WHATWG
 * serialisation.
 *
 * `URL.hostname` keeps the brackets on an IPv6 literal (`[::1]`) and always
 * serialises it compressed, while an operator may write the entry bracketed
 * or bare, expanded or compressed. Comparing raw strings meant an IPv6 entry
 * could never match. Routing the entry through `URL` gives it exactly the
 * serialisation the URL side will have; a literal `URL` rejects is kept as
 * written, where it matches nothing rather than something unintended.
 */
const canonicalHost = (host) => {
    const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
    if (!bare.includes(":"))
        return bare.toLowerCase();
    try {
        return new URL(`http://[${bare}]/`).hostname.slice(1, -1);
    }
    catch {
        return bare.toLowerCase();
    }
};
/**
 * Parse an allowlist entry into its host and optional port.
 *
 * Bracketed IPv6 (`[::1]:8080`) is handled by locating the port after the
 * closing bracket, so an address's own colons are not read as a separator;
 * a bare literal (`::1`) has more than one colon and no brackets, and a port
 * cannot be attached to that form, so it is read as a host alone.
 */
const splitHostPort = (entry) => {
    const trimmed = entry.trim().toLowerCase();
    if (trimmed.startsWith("[")) {
        const close = trimmed.indexOf("]");
        if (close === -1)
            return { host: canonicalHost(trimmed), port: null };
        const rest = trimmed.slice(close + 1);
        return {
            host: canonicalHost(trimmed.slice(1, close)),
            port: rest.startsWith(":") ? rest.slice(1) : null,
        };
    }
    const colon = trimmed.lastIndexOf(":");
    if (colon === -1 || trimmed.indexOf(":") !== colon) {
        return { host: canonicalHost(trimmed), port: null };
    }
    return { host: canonicalHost(trimmed.slice(0, colon)), port: trimmed.slice(colon + 1) };
};
/**
 * Every message on an error's `cause` chain, outermost first.
 *
 * undici — Node's `fetch` — reports most failures as `TypeError("fetch
 * failed")` with the actual reason on `cause`; the top-level message alone
 * tells an audit log nothing.
 */
const describeError = (err) => {
    const messages = [];
    let current = err;
    for (let depth = 0; depth < 5 && current instanceof Error; depth++) {
        messages.push(current.message);
        current = current.cause;
    }
    return messages.length > 0 ? messages.join(": ") : String(err);
};
/**
 * Read at most `maxBytes` from the body, aborting as soon as the cap is
 * passed.
 *
 * `Content-Length` is checked first as a cheap rejection, but it is a claim
 * made by the responder and is not relied on: a responder that lies, or omits
 * it under chunked encoding, is caught by the running total instead.
 */
const readCapped = async (response, maxBytes) => {
    const declared = response.headers.get("content-length");
    if (declared !== null && Number(declared) > maxBytes)
        return { ok: false };
    const body = response.body;
    if (body === null)
        return { ok: true, bytes: new Uint8Array(0) };
    const reader = body.getReader();
    const chunks = [];
    let total = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done)
                break;
            total += value.byteLength;
            if (total > maxBytes) {
                await reader.cancel();
                return { ok: false };
            }
            chunks.push(value);
        }
    }
    finally {
        reader.releaseLock();
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return { ok: true, bytes };
};
export const createGuardedFetch = (options) => {
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    const allowed = options.allowedHosts.map(splitHostPort);
    const hostAllowed = (url) => allowed.some((entry) => {
        if (entry.host !== canonicalHost(url.hostname))
            return false;
        return entry.port === null || entry.port === (url.port === "" ? defaultPort(url) : url.port);
    });
    const defaultPort = (url) => (url.protocol === "https:" ? "443" : "80");
    return async (rawUrl) => {
        let url;
        try {
            url = new URL(rawUrl);
        }
        catch {
            return { ok: false, reason: "url_unparseable", detail: rawUrl };
        }
        // http is normal for CRL distribution points — a CRL is signed, so its
        // transport does not carry the trust — but nothing else is.
        if (url.protocol !== "http:" && url.protocol !== "https:") {
            return { ok: false, reason: "scheme_not_allowed", detail: url.protocol };
        }
        // Credentials in the URL would be sent by us to a destination a
        // certificate named. There is no legitimate CRL that needs them.
        if (url.username !== "" || url.password !== "") {
            return { ok: false, reason: "url_has_credentials", detail: url.host };
        }
        if (!hostAllowed(url)) {
            return { ok: false, reason: "host_not_allowed", detail: url.host };
        }
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), options.timeoutMs);
        try {
            const response = await fetchImpl(url, {
                method: "GET",
                // A redirect names a second destination that the allowlist never
                // vetted, and following one is how an allowlisted host becomes an
                // open proxy into everything it can reach.
                redirect: "error",
                signal: controller.signal,
                credentials: "omit",
                headers: { accept: "application/pkix-crl, application/octet-stream, */*" },
            });
            if (!response.ok) {
                return { ok: false, reason: "http_error", detail: `HTTP ${response.status}` };
            }
            const body = await readCapped(response, options.maxBytes);
            if (!body.ok) {
                return {
                    ok: false,
                    reason: "response_too_large",
                    detail: `exceeded ${options.maxBytes} bytes`,
                };
            }
            return { ok: true, bytes: body.bytes };
        }
        catch (err) {
            const message = describeError(err);
            if (controller.signal.aborted) {
                return { ok: false, reason: "timeout", detail: `${options.timeoutMs}ms` };
            }
            // `redirect: "error"` surfaces as a TypeError from fetch — with the
            // reason on `cause` under undici; naming it separately keeps the
            // audit trail honest about which limit fired.
            if (/redirect/i.test(message)) {
                return { ok: false, reason: "redirect_refused", detail: message };
            }
            return { ok: false, reason: "network_error", detail: message };
        }
        finally {
            clearTimeout(timer);
        }
    };
};
