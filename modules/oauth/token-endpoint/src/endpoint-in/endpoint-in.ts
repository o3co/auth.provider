import { audit } from "@mod/audit";
import { clients } from "@mod/clients";
import { type Grant, sessionIssuances, targets } from "@mod/grants";
import type { BuildContext } from "@mod/kernel";
import { clientBindings, senderBinding } from "@mod/sender-binding";
import { tokens } from "@mod/tokens";
import { tokenEndpoint } from "../route/endpoint.ts";

/** What `endpointIn` takes from the build context (its own `targets` aside, which the module provides). */
export const endpointTakes = [
	clients,
	tokens,
	sessionIssuances,
	senderBinding,
	clientBindings,
	audit,
] as const;

/** The endpoint's handler over the contracts the assembly gives, dispatching to the grants composed. */
export const endpointIn = async (c: BuildContext<unknown>, composed: readonly Grant[]) =>
	tokenEndpoint({
		clients: await c.get(clients),
		tokens: await c.get(tokens),
		told: await c.collect(sessionIssuances),
		bindings: await c.get(senderBinding),
		required: await c.get(clientBindings),
		grants: new Map(composed.map((g) => [g.grantType, g])),
		targets: await c.get(targets),
		audit: await c.get(audit),
	});
