import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { kernelConfig } from "@mod/kernel";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import senderBindingModule from "@mod/sender-binding/module";
import type { AccessGrant, IssueLimits, Tokens } from "../src/contract.ts";
import tokensModule from "../src/module.ts";

/** What a test's composition of tokens holds at least: http, keys, issuer, sender-binding and tokens. */
export const composedModules = [http, keysModule, issuerModule, senderBindingModule, tokensModule];

/** Their sections, tokens' own left to each test. */
export const composedConfig = () => ({
	...kernelConfig(),
	...httpConfig(),
	...keysConfig(),
	...issuerConfig(),
});

/** Issues through `issue`, which nothing in the tests using it refuses, and answers what it issued. */
export async function issueFor(t: Tokens, grant: AccessGrant, limits?: IssueLimits) {
	const issued = await t.issue({ grant, grantType: "test" }, limits);
	if (issued.kind !== "issued") throw new Error(`refused by ${issued.policy}`);
	return issued.access;
}
