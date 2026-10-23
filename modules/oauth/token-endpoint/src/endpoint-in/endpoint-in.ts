import { audit } from "@mod/audit";
import { clients } from "@mod/clients";
import { type Grant, sessionIssuances, targets } from "@mod/grants";
import type { BuildContext } from "@mod/kernel";
import { clientBindings, senderBinding } from "@mod/sender-binding";
import { tokens } from "@mod/tokens";
import { tokenEndpoint } from "../route/endpoint.ts";

/** The endpoint's handler over the contracts the assembly gives, dispatching to the grants composed. */
export const endpointIn = async (c: BuildContext<unknown>, composed: readonly Grant[]) =>
	tokenEndpoint(
		await c.get(clients),
		await c.get(tokens),
		await c.collect(sessionIssuances),
		await c.get(senderBinding),
		await c.get(clientBindings),
		new Map(composed.map((g) => [g.grantType, g])),
		await c.get(targets),
		await c.get(audit),
	);
