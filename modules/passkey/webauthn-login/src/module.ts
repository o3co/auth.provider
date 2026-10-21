import { grants } from "@mod/grants";
import { routes } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { passkeyGrantIn } from "./grant/grant.ts";
import { optionsRouteIn } from "./options/options.ts";
import { section } from "./section.ts";

export default defineModule({ name: "webauthn-login", section, replicaSafe: true }, (m) => [
	m.contribute(grants).by(passkeyGrantIn),
	m.contribute(routes).by(optionsRouteIn),
]);
