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
 * `standardDevelopmentMailSenderModule`: fills the `mailSender` slot with the
 * development sender, over the composition's `logger` (or `consoleLogger`).
 * It has no settings, so no section. Its factory runs at every boot, whether
 * or not anything reads the slot, and lets the sender in only where the
 * environment it is told — the name the configuration was selected by —
 * reads as development or test: an allow-list, since a code in a log line is
 * a secret anywhere else. It refuses too where that name, `CONFIG_ENV` or
 * `NODE_ENV` reads as production or staging (core's `productionEnvironmentIn`),
 * none lifting another's, and where the `deploymentMode` slot says `multi`. A
 * name or a slot it cannot read is a `TypeError`. Stateless.
 */

import {
	consoleLogger,
	type DeploymentMode,
	defineModule,
	type Module,
	productionEnvironmentIn,
	readEnvironmentName,
} from "@o3co/auth-provider-core";
import { createStandardDevelopmentMailSender } from "./sender.mjs";

const NAME = "standard-development-mail-sender";

/** The environments the sender is let into. */
const DEVELOPMENT_NAMES: ReadonlySet<string> = new Set(["development", "test"]);

const DEPLOYMENT_MODES: ReadonlySet<unknown> = new Set<DeploymentMode>([
	"single",
	"multi",
	"unset",
]);

export interface StandardDevelopmentMailSenderModuleOptions {
	/**
	 * The name the deployment selected its configuration by — the standalone
	 * template passes `CONFIG_ENV || NODE_ENV || "development"`.
	 */
	readonly environment: string;
}

/** Why the development sender may not run here, or none. */
function refusals(environment: string, deploymentMode: DeploymentMode): string[] {
	const production = productionEnvironmentIn([
		environment,
		process.env.CONFIG_ENV,
		process.env.NODE_ENV,
	]);
	const name = readEnvironmentName(environment) ?? "";
	return [
		...(production !== undefined
			? [`the environment is "${production}"`]
			: DEVELOPMENT_NAMES.has(name)
				? []
				: [`the environment "${name}" is not development or test`]),
		...(deploymentMode === "multi" ? ['core.deployment.mode is "multi"'] : []),
	];
}

/** The development sender's module, for the environment the configuration was selected by. */
export function standardDevelopmentMailSenderModule(
	options: StandardDevelopmentMailSenderModuleOptions,
): Module {
	const environment: unknown = options?.environment;
	return defineModule({
		name: NAME,
		requires: ["deploymentMode"] as const,
		optional: ["logger"] as const,
		lifecycle: { mailSender: { eager: true } },
		provides: {
			mailSender: ({ deploymentMode, logger }) => {
				if (typeof environment !== "string") {
					throw new TypeError(
						`${NAME}: environment must be the name the configuration was selected by`,
					);
				}
				if (!DEPLOYMENT_MODES.has(deploymentMode)) {
					throw new TypeError(`${NAME}: deploymentMode must be "single", "multi" or "unset"`);
				}
				const reasons = refusals(environment, deploymentMode);
				if (reasons.length > 0) {
					throw new RangeError(
						`${NAME} logs every code it is handed, refused because ${reasons.join(" and ")}: install standard-smtp-mail-sender, or a mail sender of your own`,
					);
				}
				return createStandardDevelopmentMailSender({ logger: logger ?? consoleLogger });
			},
		},
	});
}
