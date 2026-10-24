import { grantsBrowsers } from "@mod/federation-grants";
import { defineModule } from "@mod/kernel";
import { connectOver } from "./connect/connect.ts";
import { name, section } from "./section.ts";

export default defineModule({ name, section }, (m) => [
	m.contribute(grantsBrowsers).by(connectOver),
]);
