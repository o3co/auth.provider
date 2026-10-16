import type { HttpRequest } from "@mod/http";
import { Unavailable } from "@mod/kernel";
import type { Reading } from "./binding.ts";
import {
	type Admission,
	challengeOf,
	type Scene,
	type SenderBindings,
	sameBinding,
	type TokenCheck,
	type TokenValidity,
} from "./contract.ts";

type Valid<C extends TokenCheck> = Extract<C, { kind: "valid" }>;
const isValid = <C extends TokenCheck>(check: C): check is Valid<C> => check.kind === "valid";

/** A scheme, then RFC 6750's b64token. */
const credentials = /^\S+ +([A-Za-z0-9\-._~+/]+=*)$/;

/** RFC 6750 and RFC 9449 at a resource: the scheme, the token's validity, then its holder. */
export async function admit<C extends TokenCheck>(
	request: HttpRequest,
	tokens: TokenValidity<C>,
	bindings: Pick<SenderBindings, "tokenTypeOf"> & {
		readBinding(request: HttpRequest, scene: Scene): Promise<Reading>;
	},
	/** Every token type a kind makes, Bearer first. */
	schemes: readonly string[],
): Promise<Admission<C>> {
	const refuse = (
		status: 400 | 401,
		scheme: string,
		error: string,
		headers?: Readonly<Record<string, string>>,
	): Admission<C> => ({
		kind: "refused",
		status,
		error,
		// A kind's own headers come last, so they may replace the challenge.
		headers: { ...challengeOf(scheme, error), ...headers },
	});
	const authorization = request.headers.get("authorization") ?? "";
	const presented = authorization.split(" ")[0]?.toLowerCase();
	const scheme = schemes.find((s) => s.toLowerCase() === presented);
	// A scheme with nothing after it presents no token, as no Authorization does (RFC 6750 §3.1).
	if (!scheme || authorization.slice(presented?.length ?? 0).trim() === "") {
		return { kind: "refused", status: 401, headers: { "www-authenticate": schemes.join(", ") } };
	}
	const token = credentials.exec(authorization)?.[1];
	if (!token) return refuse(400, scheme, "invalid_request");
	const check = await tokens.verifyAccess(token);
	if (!isValid(check)) return refuse(401, scheme, "invalid_token");
	const held = check.binding;
	const tokenType = held ? bindings.tokenTypeOf(held.member) : "Bearer";
	if (tokenType === undefined) return refuse(401, scheme, "invalid_token");
	// A bound token presented as another type is refused, so binding cannot be stripped.
	if (tokenType !== scheme) return refuse(401, tokenType, "invalid_token");
	if (held) {
		const read = await bindings.readBinding(request, { kind: "resource", token });
		if (read.kind === "refused") {
			if (read.unavailable) throw new Unavailable("sender binding");
			// Challenged in the refusing kind's scheme, whose error code it is (RFC 9449, RFC 8705).
			return refuse(401, read.scheme, read.error, read.headers);
		}
		if (read.kind === "multiple_bindings") return refuse(400, scheme, "invalid_request");
		const proved = read.kind === "bound" ? read.binding : undefined;
		if (!sameBinding(held, proved)) return refuse(401, scheme, "invalid_token");
	}
	return { kind: "admitted", access: check };
}
