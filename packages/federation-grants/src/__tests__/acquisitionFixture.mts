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
 * What every composition that enables federation grants now brings (#593
 * slice 6): a consent page, a callback per connection on the provider's own
 * origin, somewhere to lodge an intent, and the identity lookup D7 check 5
 * asks. The tests that exercise spending a grant need all of it present and
 * none of it to be what they are about — so it lives here once.
 */

import { createMemoryFederationGrantIntentStore, defineModule } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";

const ISSUER = (makeValidCoreConfig() as { oauth: { jwt: { issuer: string } } }).oauth.jwt.issuer;

/** Merged into `federationGrants`. */
export const ACQUISITION_GRANT_SETTINGS = { consent: { url: "/consent/grants" } } as const;

/** A connection's `callbackURL` on the test issuer's origin. */
export const callbackUrlFor = (connection: string): string =>
	`${new URL(ISSUER).origin}/session/federation-grants/callback/${connection}`;

/** Merged into `bootstrapComponents`. The lookup answers "linked to nobody". */
export const acquisitionComponents = () => ({
	federationGrantIntentStore: createMemoryFederationGrantIntentStore(),
	userRepository: {
		authenticate: async () => null,
		authenticateByToken: async () => null,
		findSubjectByFederatedIdentity: async () => null,
	},
});

/**
 * A stand-in for `sessionStoreModule`'s `session-middleware` route, which the
 * browser half mounts after. In a real composition that is express-session;
 * these tests log nobody in, so a pass-through is all `after` needs to find.
 */
export const sessionMiddlewareModule = defineModule({
	name: "test-session-middleware",
	contributes: {
		routes: [
			() => ({
				id: "session-middleware",
				mountPath: "/",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			}),
		],
	},
});
