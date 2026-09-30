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
 * or not anything reads the slot, and refuses the boot where the
 * configuration was selected as production or staging, where `NODE_ENV` is
 * either — each read whatever its case and the whitespace around it — and
 * where the `deploymentMode` slot says `multi`: a multi-replica deployment is
 * never a development box. A slot it cannot read is a `TypeError`. Stateless.
 */

import {
	consoleLogger,
	type DeploymentMode,
	defineModule,
	type Module,
} from "@o3co/auth-provider-core";
import { createStandardDevelopmentMailSender } from "./sender.mjs";

const NAME = "standard-development-mail-sender";

const PRODUCTION_ENVIRONMENTS: ReadonlySet<string> = new Set(["production", "staging"]);

const DEPLOYMENT_MODES: ReadonlySet<unknown> = new Set<DeploymentMode>([
	"single",
	"multi",
	"unset",
]);

export interface StandardDevelopmentMailSenderModuleOptions {
	/**
	 * The name the deployment selected its configuration by — the standalone
	 * template passes `CONFIG_ENV || NODE_ENV`. `NODE_ENV` is read beside it
	 * either way.
	 */
	readonly environment?: string;
}

/** Why the development sender may not run here, or none. */
function refusals(environment: string | undefined, deploymentMode: DeploymentMode): string[] {
	const production = [environment, process.env.NODE_ENV]
		.map((name) => (typeof name === "string" ? name.trim().toLowerCase() : undefined))
		.find((name): name is string => name !== undefined && PRODUCTION_ENVIRONMENTS.has(name));
	return [
		...(production === undefined ? [] : [`the environment is "${production}"`]),
		...(deploymentMode === "multi" ? ['core.deployment.mode is "multi"'] : []),
	];
}

/** The development sender's module, for the environment the configuration was selected by. */
export function standardDevelopmentMailSenderModule(
	options: StandardDevelopmentMailSenderModuleOptions = {},
): Module {
	return defineModule({
		name: NAME,
		requires: ["deploymentMode"] as const,
		optional: ["logger"] as const,
		lifecycle: { mailSender: { eager: true } },
		provides: {
			mailSender: ({ deploymentMode, logger }) => {
				if (!DEPLOYMENT_MODES.has(deploymentMode)) {
					throw new TypeError(`${NAME}: deploymentMode must be "single", "multi" or "unset"`);
				}
				const reasons = refusals(options.environment, deploymentMode);
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
