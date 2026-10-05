/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The outbound fetch for tests: the same policy over a resolver and a
 * transport a test supplies (both below the policy, so every rule still
 * applies), the error class a test asserts on, and the builder a test writes
 * `core.outbound` with.
 */

import type { z } from "zod";
import {
	buildOutboundFetch,
	type OutboundFetchOptions,
	systemLookup,
} from "../net/outbound-fetch.mjs";
import type { OutboundSectionSchema } from "../net/outbound-policy.mjs";
import { nodeTransport, type OutboundTransport } from "../net/outbound-transport.mjs";

export { OutboundFetchError } from "../net/outbound-policy.mjs";
export type {
	OutboundAnswer,
	OutboundExchange,
	OutboundTransport,
} from "../net/outbound-transport.mjs";

export type OutboundFetchForTestingOptions = OutboundFetchOptions & {
	/** Answers a host name with its addresses; absent → the system resolver. */
	readonly lookup?: (hostname: string) => Promise<readonly string[]>;
	/** Performs the exchange with the checked addresses; absent → Node's own. */
	readonly transport?: OutboundTransport;
};

/** `createOutboundFetch`, with the resolver and the transport replaced where given. */
export function createOutboundFetchForTesting(
	options: OutboundFetchForTestingOptions,
): typeof fetch {
	const { lookup, transport, ...rest } = options;
	return buildOutboundFetch(rest, {
		lookup: lookup ?? systemLookup,
		transport: transport ?? nodeTransport,
	});
}

/** `core.outbound` as a test writes it. */
export type OutboundSectionForTests = z.input<typeof OutboundSectionSchema>;

/**
 * A copy of `config` whose `core.outbound` is `outbound`, every other key of
 * `core` and of `config` kept; `config` itself is left as it was.
 */
export function withOutbound<C extends object>(
	config: C,
	outbound: OutboundSectionForTests,
): C & { readonly core: { readonly outbound: OutboundSectionForTests } } {
	const core = (config as { readonly core?: Readonly<Record<string, unknown>> }).core;
	return { ...config, core: { ...core, outbound } } as C & {
		readonly core: { readonly outbound: OutboundSectionForTests };
	};
}
