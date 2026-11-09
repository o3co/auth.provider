import type { Client } from "@mod/clients";
import { type HttpRequest, noStore } from "@mod/http";
import type { Grant } from "../../grant/grant.ts";
import type { ApiCommon } from "../common.ts";

/** A grant revoked by its client. */
export function revokingWith({ p, records, record }: ApiCommon) {
	const revoke = async (request: HttpRequest, client: Client, grant: Grant) => {
		const at = p.clock.now();
		const changed = await p.grants.change(grant.id, (stored) => {
			const now = records.grantOf(stored);
			if (!now || now.status === "revoked") return undefined;
			const revoked = p.revocation(now, "client", at);
			return { value: records.stored(revoked.grant), lifetimeMs: revoked.lifetimeMs };
		});
		if (records.grantOf(changed?.before)?.status !== "revoked" && changed) {
			await p.unlisted(grant);
			record(
				"federation.grant.revoked",
				grant.subject,
				{ client: client.id, connection: grant.connection, outcome: "client" },
				request,
			);
		}
		return { status: 204, headers: noStore };
	};
	return { revoke };
}
