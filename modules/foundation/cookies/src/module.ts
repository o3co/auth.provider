import { site } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { cookies } from "./contract.ts";
import { cookiesFor } from "./cookies.ts";

export default defineModule({ name: "cookies" }, (m) => [
	m.provide(cookies).by(async (c) => cookiesFor((await c.get(site)).secureCookies)),
]);
