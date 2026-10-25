import type { Authentication, Client, Clients } from "@mod/clients";
import type { Grant, GrantInput, GrantOutcome } from "@mod/grants";
import type { HttpRequest } from "@mod/http";
import { Unavailable } from "@mod/kernel";

/**
 * The grant that identifies the client of a request naming none: one `clients` refuses as
 * `no_credentials` and finds `bare`, whose one `grant_type` names a grant with `identify`. None for
 * any other request, which is answered as its authentication says.
 */
export function identifierOf(
	clients: Pick<Clients, "bare">,
	grants: ReadonlyMap<string, Grant>,
	authenticated: Authentication,
	request: HttpRequest,
	grantType: string | undefined,
): Grant | undefined {
	// Both, as the contract says: a bare request is refused only so today, which `bare` alone does not promise.
	if (authenticated.kind !== "refused" || authenticated.reason !== "no_credentials") {
		return undefined;
	}
	if (!clients.bare(request)) return undefined;
	const grant = grants.get(grantType ?? "");
	return grant?.identify ? grant : undefined;
}

/**
 * The client the grant identifies, with what it identified, or the grant's refusal as it gives it.
 * Only a client registered as public with method `none` may be one: any other would skip its own
 * authentication (`clients` registers a confidential client with `none`, and only refuses to
 * authenticate it). Boot checks keep another from coming; past them, it cannot tell.
 */
export async function identifiedClient(
	clients: Pick<Clients, "find">,
	grant: Grant,
	input: Pick<GrantInput, "request" | "param" | "value">,
): Promise<
	| { readonly kind: "client"; readonly client: Client; readonly identified?: unknown }
	| Extract<GrantOutcome, { readonly kind: "error" }>
> {
	const identity = await grant.identify?.(input);
	// Cannot come: `identifierOf` names only a grant with `identify`.
	if (identity === undefined) throw new Unavailable("token-endpoint");
	if (identity.kind === "error") return identity;
	const found = await clients.find(identity.client);
	if (!found?.registered || found.kind !== "public" || found.method !== "none") {
		throw new Unavailable("token-endpoint");
	}
	return { kind: "client", client: found, identified: identity.identified };
}
