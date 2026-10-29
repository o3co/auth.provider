import { defineModule } from "@mod/kernel";
import { tlsOptions } from "./contract.ts";
import { optionsOf } from "./options.ts";
import { section } from "./section.ts";

export default defineModule({ name: "tls-options", section, replicaSafe: true, takes: [] }, (m) => [
	m.provide(tlsOptions).by((c) => optionsOf(c.section)),
]);
