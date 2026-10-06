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
 * The module that fills the `sessionLifecycle` slot: the lifecycle service
 * over the session stores, and the sweep that resumes pending closes every
 * `core.sessionLifecycle.sweepIntervalSeconds` unless that is 0.
 *
 * The notifier is a contribution (`sessionCloseNotifiers`), read through the
 * synthetic `sessionCloseNotifierResolver` when a close runs, never while
 * modules are built: so the module contributing it is not ordered before
 * this one, and may read slots of a module that requires `sessionLifecycle`.
 * Boot refuses, at the end of the contributions, a composition that serves
 * relying parties (the `clientRepository` slot is filled) and contributes no
 * notifier (`SESSION_LIFECYCLE_NOTIFIER_MISSING`). Boot orders modules, not
 * components, so the refresh-token lifetime is read from the configuration,
 * not from the oauth module's slot.
 */

import {
	type RefreshTokenLifetimeSource,
	resolveRefreshTokenLifetime,
} from "../config/application.schema.mjs";
import { configuredNumber, shownConfigValue } from "../config/configuredValue.mjs";
import { MAX_DURATION_MS } from "../config/durations.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "../jwt/verify.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import { defineModule } from "../modules/manifest/define-module.mjs";
import { createSessionLifecycle } from "./service.mjs";
import { startSessionLifecycleSweeper } from "./sweeper.mjs";

const SWEEP_KEY = "core.sessionLifecycle.sweepIntervalSeconds";

/**
 * The sweep interval when `core.sessionLifecycle.sweepIntervalSeconds` is not
 * written, in whole seconds: a close left pending, its user session already
 * gone, waits at most this long for no later close to resume it.
 */
export const DEFAULT_SESSION_LIFECYCLE_SWEEP_INTERVAL_SECONDS = 60;

/** The longest sweep interval, in whole seconds: the longest delay a timer takes. */
export const MAX_SESSION_LIFECYCLE_SWEEP_INTERVAL_SECONDS = Math.floor(2_147_483_647 / 1000);

/**
 * `core.sessionLifecycle.sweepIntervalSeconds` in milliseconds, read as
 * core's numbers are (`configuredNumber`):
 * {@link DEFAULT_SESSION_LIFECYCLE_SWEEP_INTERVAL_SECONDS} when it is not
 * written, and `undefined` for 0, which turns the sweep off. Anything but a
 * whole number of seconds from 0 to
 * {@link MAX_SESSION_LIFECYCLE_SWEEP_INTERVAL_SECONDS} is a RangeError naming
 * the key.
 */
export function readSessionLifecycleSweepIntervalMs(config: unknown): number | undefined {
	const value = (
		config as { core?: { sessionLifecycle?: { sweepIntervalSeconds?: unknown } } } | undefined
	)?.core?.sessionLifecycle?.sweepIntervalSeconds;
	// Core's reference.conf ships the default; a configuration not layered on
	// it, such as a test's fixture, reads the same.
	if (value === undefined) return DEFAULT_SESSION_LIFECYCLE_SWEEP_INTERVAL_SECONDS * 1000;
	const seconds = configuredNumber(value);
	if (
		seconds === undefined ||
		!Number.isInteger(seconds) ||
		seconds < 0 ||
		seconds > MAX_SESSION_LIFECYCLE_SWEEP_INTERVAL_SECONDS
	) {
		throw new RangeError(
			`${SWEEP_KEY} must be a whole number of seconds from 0 (no sweep) to ${MAX_SESSION_LIFECYCLE_SWEEP_INTERVAL_SECONDS} (got ${shownConfigValue(value)})`,
		);
	}
	return seconds === 0 ? undefined : seconds * 1000;
}

/**
 * How long a closing record is kept from its closing commit: the
 * refresh-token lifetime plus the clock skew it is accepted with, within the
 * port's year; 0 where no refresh token is configured. That is sound only
 * where nothing bundled mints refresh tokens: an `oauthTokenSettings` slot over
 * such a configuration is refused, and so are the default family modules. A
 * host's own grant minting refresh tokens over a family revocation of its own,
 * with no `oauthTokenSettings`, gets 0 too: such a host configures
 * `oauth.refreshToken.expiresIn` itself.
 */
const closingRetainMs = (config: unknown): number => {
	const source = config as RefreshTokenLifetimeSource | undefined;
	if (source?.oauth?.refreshToken?.expiresIn === undefined) return 0;
	return Math.min(
		MAX_DURATION_MS,
		resolveRefreshTokenLifetime(source) * 1000 + DEFAULT_CLOCK_SKEW_MS,
	);
};

export const SESSION_LIFECYCLE_MODULE = "core-session-lifecycle";

/**
 * Why boot refuses a composition that serves relying parties (the
 * `clientRepository` slot is filled) and contributes no notifier: judged at
 * the end of the contributions, once the notifier would have registered.
 */
export const SESSION_LIFECYCLE_NOTIFIER_MISSING =
	"core-session-lifecycle: relying parties are served (the clientRepository slot is filled) " +
	"and no sessionCloseNotifier is wired, so a closed session's relying parties would never " +
	"be told. Install a module that contributes a sessionCloseNotifiers entry (oauthEndpointsModule does).";

export const sessionLifecycleModule = defineModule({
	name: SESSION_LIFECYCLE_MODULE,
	requires: [
		"sessionLifecycleStore",
		"userSessionStore",
		"refreshTokenFamilyRevocation",
		"federationTokenStore",
		"config",
		// Synthetic: the contributed notifier, read when a close runs.
		"sessionCloseNotifierResolver",
	] as const,
	optional: ["subjectSessionIndex", "logger", "lifecycleRegistrar"] as const,
	// Eager: installed, the module refuses a composition without a notifier
	// and starts its sweep at boot, whether or not anything requires the slot.
	lifecycle: { sessionLifecycle: { eager: true } },
	provides: {
		sessionLifecycle: (deps) => {
			const intervalMs = readSessionLifecycleSweepIntervalMs(deps.config);
			const logger = deps.logger ?? consoleLogger;
			const lifecycle = createSessionLifecycle({
				store: deps.sessionLifecycleStore,
				userSessionStore: deps.userSessionStore,
				refreshTokenFamilyRevocation: deps.refreshTokenFamilyRevocation,
				federationTokenStore: deps.federationTokenStore,
				...(deps.subjectSessionIndex === undefined
					? {}
					: { subjectSessionIndex: deps.subjectSessionIndex }),
				notifier: () => deps.sessionCloseNotifierResolver.get(),
				retainMs: closingRetainMs(deps.config),
				logger,
			});
			if (intervalMs !== undefined) {
				const sweeper = startSessionLifecycleSweeper(lifecycle, intervalMs, logger);
				deps.lifecycleRegistrar?.register(() => sweeper.stop());
			}
			return lifecycle;
		},
	},
});
