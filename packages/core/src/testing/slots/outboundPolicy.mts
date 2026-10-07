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
 * The test double of the `outboundPolicy` slot: `createTestOutboundPolicy`
 * reads the section a test writes with core's reader of `core.outbound`.
 */

import { outboundPolicyOf } from "../../net/outbound-fetch.mjs";
import type { OutboundPolicy } from "../../net/outbound-policy.mjs";
import type { OutboundSectionForTests } from "../outboundFetch.mjs";

/** The policy `section` states as `core.outbound`, read by core's reader; the defaults when absent. */
export function createTestOutboundPolicy(section: OutboundSectionForTests = {}): OutboundPolicy {
	return outboundPolicyOf({ core: { outbound: section } });
}
