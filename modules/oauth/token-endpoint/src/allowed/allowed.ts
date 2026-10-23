import { clientAllowance } from "@mod/client-allowance";
import type { Client } from "@mod/clients";
import { grantServers } from "@mod/grants";
import type { Refusal } from "@mod/kernel";

/**
 * Where a registered client is allowed a grant nothing composed serves, each by its place in the
 * client's list, naming the module that serves it where `grants`' index knows it; never the
 * client's id or the grant type, which are the settings' values.
 */
export function unservedGrants(
	registered: readonly Client[],
	composed: ReadonlySet<string>,
): Refusal[] {
	return registered.flatMap((client, i) =>
		clientAllowance.grantsOf(client).flatMap((grantType, j) => {
			if (composed.has(grantType)) return [];
			const server = grantServers[grantType] ?? "the module that serves it";
			return [
				{
					where: `clients.registered.${i}.sections.client-allowance.grants.${j}`,
					reason: `no composed module serves this grant: compose ${server}, or take it out of the client's grants`,
				},
			];
		}),
	);
}
