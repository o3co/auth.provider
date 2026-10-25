import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import senderBindingModule from "../src/module.ts";

it("takes all it names, under either dispatch", async () => {
	for (const dispatch of ["intent-explicit", "strict-mutual-exclusion"]) {
		const input = {
			modules: [http, issuerModule, senderBindingModule],
			config: {
				...kernelConfig(),
				...httpConfig(),
				...issuerConfig(),
				"sender-binding": { dispatch },
			},
		};
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect((await takesUnused(input))["sender-binding"], dispatch).toBeUndefined();
	}
});
