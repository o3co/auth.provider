import { createHash } from "node:crypto";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { expired, type Ring } from "../signing/ring.ts";

const cacheControl = "public, max-age=300";

function etagMatches(header: string | undefined, etag: string): boolean {
	return header?.split(",").some((tag) => tag.trim() === etag) ?? false;
}

export function jwksResponse(ring: Ring, now: number, request: HttpRequest): HttpResponse {
	const published = ring.publicKeys.filter((k) => !expired(k, () => now));
	if (published.length === 0) {
		return jsonAnswer(404, { error: "jwks_not_published" });
	}
	const body = JSON.stringify({
		keys: published.map((k) => ({
			...k.key.export({ format: "jwk" }),
			kid: k.kid,
			alg: k.alg,
			use: "sig",
		})),
	});
	const etag = `"${createHash("sha256").update(body).digest("base64url")}"`;
	const headers = { etag, "cache-control": cacheControl };
	if (etagMatches(request.headers.get("if-none-match"), etag)) return { status: 304, headers };
	return { status: 200, headers: { ...headers, "content-type": "application/json" }, body };
}
