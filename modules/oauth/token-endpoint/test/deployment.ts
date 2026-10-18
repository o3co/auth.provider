import clientsModule from "@mod/clients/module";
import http from "@mod/http/module";
import { type HttpSettings, httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { kernelConfig, type Module } from "@mod/kernel";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import secretHashModule from "@mod/secret-hash/module";
import senderBindingModule from "@mod/sender-binding/module";
import tokensModule from "@mod/tokens/module";
import { tokensConfig } from "@mod/tokens/testing";
import tokenEndpoint from "../src/module.ts";

/** The token endpoint and the modules it cannot run without, then `extra`. */
export const endpointModules = (...extra: Module[]): Module[] => [
	http,
	keysModule,
	tokensModule,
	issuerModule,
	senderBindingModule,
	clientsModule,
	secretHashModule,
	tokenEndpoint,
	...extra,
];

/** Their configuration, with http's `peer` settings and the issuer at `issuer` when given. */
export const endpointConfig = ({
	peer = {},
	issuer,
}: {
	peer?: Partial<HttpSettings>;
	issuer?: string;
} = {}) => ({
	...kernelConfig(),
	...httpConfig(peer),
	...keysConfig(),
	...issuerConfig(issuer === undefined ? {} : { url: issuer }),
	...tokensConfig(),
});

/** The Basic authorization of a client by its id and secret. */
export const basicOf = (id: string, secret: string) =>
	`Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;
