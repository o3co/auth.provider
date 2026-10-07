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
 * or not anything reads the slot, and lets the sender in only where every
 * name it reads says development or test — the environment it is told (the
 * name the configuration was selected by), and `CONFIG_ENV` and `NODE_ENV`
 * where they are set: an allow-list over each, since a code in a log line
 * is a secret anywhere else, and none lifts another's refusal. A name that
 * says production or staging (core's `productionEnvironmentIn`) is refused
 * as that; any other as not development or test. It refuses too where the
 * `deploymentMode` slot says `multi`. A name or a slot it cannot read is a
 * `TypeError`. Stateless.
 */
import { consoleLogger, defineModule, productionEnvironmentIn, readEnvironmentName, } from "@o3co/auth-provider-core";
import { createStandardDevelopmentMailSender } from "./sender.mjs";
const NAME = "standard-development-mail-sender";
/** The environments the sender is let into. */
const DEVELOPMENT_NAMES = new Set(["development", "test"]);
const DEPLOYMENT_MODES = new Set([
    "single",
    "multi",
    "unset",
]);
/** Why `value`, read as `label`, keeps the sender out, or none. */
function refusalOf(label, value) {
    const production = productionEnvironmentIn([value]);
    if (production !== undefined)
        return `${label} is "${production}"`;
    const name = readEnvironmentName(value) ?? "";
    return DEVELOPMENT_NAMES.has(name) ? undefined : `${label} "${name}" is not development or test`;
}
/** Why the development sender may not run here, or none: each name it reads, then the deployment mode. */
function refusals(environment, deploymentMode) {
    const named = [["the environment", environment]];
    for (const variable of ["CONFIG_ENV", "NODE_ENV"]) {
        const value = process.env[variable];
        // A variable that is not set, or empty, names nothing.
        if (readEnvironmentName(value) !== undefined)
            named.push([variable, value]);
    }
    return [
        ...named.flatMap(([label, value]) => refusalOf(label, value) ?? []),
        ...(deploymentMode === "multi" ? ['core.deployment.mode is "multi"'] : []),
    ];
}
/** The development sender's module, for the environment the configuration was selected by. */
export function standardDevelopmentMailSenderModule(options) {
    const environment = options?.environment;
    return defineModule({
        name: NAME,
        requires: ["deploymentMode"],
        optional: ["logger"],
        lifecycle: { mailSender: { eager: true } },
        provides: {
            mailSender: ({ deploymentMode, logger }) => {
                if (typeof environment !== "string") {
                    throw new TypeError(`${NAME}: environment must be the name the configuration was selected by`);
                }
                if (!DEPLOYMENT_MODES.has(deploymentMode)) {
                    throw new TypeError(`${NAME}: deploymentMode must be "single", "multi" or "unset"`);
                }
                const reasons = refusals(environment, deploymentMode);
                if (reasons.length > 0) {
                    throw new RangeError(`${NAME} logs every code it is handed, refused because ${reasons.join(" and ")}: install standard-smtp-mail-sender, or a mail sender of your own`);
                }
                return createStandardDevelopmentMailSender({ logger: logger ?? consoleLogger });
            },
        },
    });
}
