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
 * The package's sections in a configuration built by hand: the grant
 * switches at their modules' sections, and the captures boot requires of the
 * variables the modules declare renamed.
 */

import type { FederationSettings, Module, OutboundPolicy } from "@o3co/auth-provider-core";
import {
	createTestFederationSettings,
	createTestOutboundPolicy,
	renamedVariableCaptures,
} from "@o3co/auth-provider-core/testing";
import { oauthEndpointsModule } from "#/module.mjs";
import { oauthAuthorizationGrantsModule } from "#/oauthAuthorization.mjs";
import { oauthSessionGrantModule } from "#/oauthSession.mjs";
import type { OAuthSection } from "#/section.mjs";

/**
 * `config` with what a resolution of the modules' references under an
 * environment that sets none of their variables captures of the names they
 * declare renamed (`null` each), beside what `config` already captures.
 */
export function capturing<C extends object>(config: C, modules: readonly Module[]): C {
	const captured = (config as { "renamed-variables"?: Record<string, unknown> })[
		"renamed-variables"
	];
	return {
		...config,
		"renamed-variables": { ...captured, ...renamedVariableCaptures({ modules, env: {} }) },
	};
}

/**
 * `config` with the captures of every rename the package's modules declare,
 * as a resolution of the package's reference under an empty environment makes
 * them: what boot requires of a configuration handed to a composition that
 * loads any of them.
 */
export function withOauthCaptures<C extends object>(config: C): C {
	return capturing(config, [
		oauthEndpointsModule,
		oauthSessionGrantModule,
		oauthAuthorizationGrantsModule,
	]);
}

/** A grant switch as a configuration may carry it: a boolean, or an environment variable's string. */
type Switch = boolean | string;

/** The switches `withGrants` sets: `session` is `oauth-session`'s, the rest `oauth-authorization`'s. */
export interface GrantSwitches {
	readonly session?: Switch;
	readonly authorizationCode?: Switch;
	readonly refreshToken?: Switch;
	readonly clientCredentials?: Switch;
	readonly jwtBearer?: Switch;
}

/**
 * `config` with the grant switches `switches` names set, each at its module's
 * section (`oauth-session.enabled`, `oauth-authorization.grants.<grant>.enabled`),
 * the others as `config` has them.
 */
export function withGrants<C extends object>(config: C, switches: GrantSwitches): C {
	const { session, ...grants } = switches;
	const base = config as {
		"oauth-session"?: Record<string, unknown>;
		"oauth-authorization"?: { grants?: Record<string, unknown> };
	};
	return {
		...config,
		"oauth-session": {
			...base["oauth-session"],
			...(session === undefined ? {} : { enabled: session }),
		},
		"oauth-authorization": {
			...base["oauth-authorization"],
			grants: {
				...base["oauth-authorization"]?.grants,
				...Object.fromEntries(
					Object.entries(grants)
						.filter(([, value]) => value !== undefined)
						.map(([grant, enabled]) => [grant, { enabled }]),
				),
			},
		},
	};
}

/**
 * What `createOAuthRouter` takes of a configuration built by hand: its
 * `oauth {}` as the router's section, as written, core's view of the
 * federations with none declared, and core's outbound policy at its defaults.
 */
export function routerInputsOf(config: object): {
	readonly section: OAuthSection;
	readonly federationSettings: FederationSettings;
	readonly outboundPolicy: OutboundPolicy;
} {
	return {
		section: (config as { readonly oauth?: unknown }).oauth as OAuthSection,
		federationSettings: createTestFederationSettings(),
		outboundPolicy: createTestOutboundPolicy(),
	};
}
