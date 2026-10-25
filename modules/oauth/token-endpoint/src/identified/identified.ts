import type { Client, Clients } from "@mod/clients";
import type { Grant, GrantInput, GrantOutcome } from "@mod/grants";
import type { HttpRequest } from "@mod/http";
import { Unavailable } from "@mod/kernel";

/**
 * The grant that identifies the client of a request naming none: one `clients` finds `bare` (which
 * it never authenticates, and refuses as `no_credentials` alone), whose one `grant_type` names a
 * grant with `identify`. None for any other request, which is answered as its authentication says.
 */
export function identifierOf(
	clients: Pick<Clients, "bare">,
	grants: ReadonlyMap<string, Grant>,
	request: HttpRequest,
	grantType: string | undefined,
): Grant | undefined {
	if (!clients.bare(request)) return undefined;
	const grant = grants.get(grantType ?? "");
	return grant?.identify ? grant : undefined;
}

/**
 * The client the grant identifies, with what it identified, or the grant's refusal as it gives it.
 * Only a client registered with no credentials (method `none`, which `clients` takes for a public
 * client alone) may be one: any other would skip its own authentication. Boot checks keep another
 * from coming; past them, it cannot tell.
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
	if (!found?.registered || found.method !== "none") throw new Unavailable("token-endpoint");
	return { kind: "client", client: found, identified: identity.identified };
}
