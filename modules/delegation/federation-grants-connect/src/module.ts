import { grantsBrowsers } from "@mod/federation-grants";
import { defineModule } from "@mod/kernel";
import { connectOver, connectTakes } from "./connect/connect.ts";
import { name, section } from "./section.ts";

export default defineModule({ name, section, takes: connectTakes }, (m) => [
	m.contribute(grantsBrowsers).by(connectOver),
]);
