import { grants } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { clientCredentials } from "./contract.ts";

export default defineModule({ name: "client-credentials" }, (m) => [
	m.contribute(grants).by(async (c) => clientCredentials((await c.get(issuer)).url)),
]);
