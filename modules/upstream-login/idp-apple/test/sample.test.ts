import { readFileSync } from "node:fs";
import { join } from "node:path";
import externalJwtModule from "@mod/external-jwt/module";
import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { outbound } from "@mod/outbound";
import { outboundRefusals } from "@mod/outbound-policy";
import { type IdpType, idpTypes } from "@mod/upstreams";
import { expect, it } from "vitest";
import idpApple from "../src/module.ts";

/** The entry sample the package ships beside its manifest, for the generated local layer's example. */
const { type, ...own } = JSON.parse(
	readFileSync(join(import.meta.dirname, "..", "entry.example"), "utf8"),
);

/** The type the module contributes to upstreams, booted with an outbound that answers nothing. */
async function contributed(): Promise<IdpType | undefined> {
	const types = contract<readonly IdpType[]>("types");
	const app = await assemble({
		modules: [
			defineModule({ name: "outbound", replicaSafe: false, takes: [] }, (m) => [
				m.provide(outbound).by(() => ({
					fetch: async () => {
						throw new Unavailable("stub");
					},
				})),
				m.provide(outboundRefusals).by(() => ({ explained: () => undefined })),
			]),
			externalJwtModule,
			idpApple,
			defineModule({ name: "types", replicaSafe: true, takes: [idpTypes] }, (m) => [
				m.provide(types).by((c) => c.collect(idpTypes)),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	return app.get(types)[0];
}

it("ships an entry sample of the type it contributes", async () => {
	expect((await contributed())?.type).toBe(type);
});

it("names in its entry sample only keys its settings take", async () => {
	const settings = (await contributed())?.settings as unknown as { shape: object };
	expect(Object.keys(own).filter((key) => !(key in settings.shape))).toEqual([]);
});
