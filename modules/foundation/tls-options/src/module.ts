import { defineModule } from "@mod/kernel";
import { tlsOptions } from "./contract.ts";
import { optionsOf } from "./options.ts";
import { section } from "./section.ts";

export default defineModule({ name: "tls-options", section, replicaSafe: true, takes: [] }, (m) => [
	m.provide(tlsOptions).by((c) => {
		// On every boot: the floor checks certificates whatever the variable says, which Node would
		// otherwise follow for a connection naming nothing; a private authority is the platform's store.
		if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
			c.log.warn("tls-options.reject_unauthorized_ignored", {
				variable: "NODE_TLS_REJECT_UNAUTHORIZED",
				reason:
					"the provider's own connections check certificates; trust a private authority by NODE_EXTRA_CA_CERTS",
			});
		}
		return optionsOf(c.section);
	}),
]);
