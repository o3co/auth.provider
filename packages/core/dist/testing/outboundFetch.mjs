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
import { buildOutboundFetch, createLookupPermits, lookupCeilingOf, systemLookup, } from "../net/outbound-fetch.mjs";
import { nodeTransport } from "../net/outbound-transport.mjs";
export { OutboundFetchError } from "../net/outbound-policy.mjs";
/**
 * `createOutboundFetch`, with the resolver and the transport replaced where
 * given. Its lookups run under a pool of its own, bounded as the process's
 * is, so a lookup one test leaves outstanding never holds a place another
 * test's fetch needs.
 */
export function createOutboundFetchForTesting(options) {
    const { lookup, transport, ...rest } = options;
    return buildOutboundFetch(rest, {
        lookup: lookup ?? systemLookup,
        lookups: createLookupPermits(lookupCeilingOf(process.env.UV_THREADPOOL_SIZE)),
        transport: transport ?? nodeTransport,
    });
}
/**
 * A copy of `config` whose `core.outbound` is `outbound`, every other key of
 * `core` and of `config` kept; `config` itself is left as it was.
 */
export function withOutbound(config, outbound) {
    const core = config.core;
    return { ...config, core: { ...core, outbound } };
}
