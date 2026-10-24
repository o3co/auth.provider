import { grants } from "@mod/grants";
import { routes } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { grantTakes, passkeyGrantIn } from "./grant/grant.ts";
import { optionsRouteIn, optionsTakes } from "./options/options.ts";
import { section } from "./section.ts";

/** What the module takes: its helpers' (`passkeyGrantIn`, `optionsRouteIn`). */
const takes = [...grantTakes, ...optionsTakes];

export default defineModule({ name: "webauthn-login", section, replicaSafe: true, takes }, (m) => [
	m.contribute(grants).by(passkeyGrantIn),
	m.contribute(routes).by(optionsRouteIn),
]);
