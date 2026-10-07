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
 * The variables renamed with a path of the composition root's own layers,
 * which no module declares: the adapter selections and the federations the
 * template ships. Phase one refuses an old name set, alone or beside its new
 * name at any value, before any module is chosen, as boot refuses a
 * variable a module declares renamed (`environment-variable-renamed`).
 * Boot's own check cannot hold these: an adapter selection decides which
 * modules are chosen before boot, and a federation's key sits in core's
 * section, whose renames core alone declares.
 */
import { variablesRenamed } from "./bootRefusal.mjs";
/**
 * Refuses, with an `environment-variable-renamed` `BootError`, an old name in
 * `env` set alone (`unset`), or beside its new name (`different`, whatever
 * either holds), in the words core refuses a module's rename in. Every such
 * rename is named at once; no value is compared, quoted or carried.
 */
export function refuseRenamedVariables(env, renames) {
    const refused = renames.flatMap((rename) => {
        const { from, to } = rename;
        if (env[from] === undefined)
            return [];
        return [
            { ...rename, state: env[to] === undefined ? "unset" : "different" },
        ];
    });
    if (refused.length === 0)
        return;
    const named = refused.map(({ from, to, path, state }) => {
        const renamed = `${from} was renamed ${to}, the variable ${path} is bound to; see the upgrade guide (docs/upgrading-from-v0.16.0.md).`;
        return state === "unset"
            ? `${renamed} Set ${to} instead and unset ${from}.`
            : `${renamed} ${to} is set as well: keep the value you mean in ${to} and unset ${from}.`;
    });
    throw variablesRenamed(`The environment sets ${refused.length} variable(s) that were renamed: ${named.join(" ")}`, refused.map(({ module, from, to, path, state }) => ({ module, from, to, path, state })));
}
/**
 * The variables `config/application.conf` binds for the two federations the
 * template ships, each renamed after its path under `core.federations`: in
 * core's section, so named under module "core" in a refusal's details.
 */
export const SHIPPED_FEDERATION_RENAMES = [
    ["GOOGLE", "google", ["ENABLED", "enabled"]],
    ["GOOGLE", "google", ["CLIENT_ID", "clientId"]],
    ["GOOGLE", "google", ["CLIENT_SECRET", "clientSecret"]],
    ["GOOGLE", "google", ["CALLBACK_URL", "callbackURL"]],
    ["GOOGLE", "google", ["ACCESS_TYPE", "accessType"]],
    ["OIDC", "oidc", ["ENABLED", "enabled"]],
    ["OIDC", "oidc", ["ISSUER", "issuer"]],
    ["OIDC", "oidc", ["CLIENT_ID", "clientId"]],
    ["OIDC", "oidc", ["CLIENT_SECRET", "clientSecret"]],
    ["OIDC", "oidc", ["CALLBACK_URL", "callbackURL"]],
].map(([federation, name, [key, path]]) => ({
    module: "core",
    from: `FEDERATIONS_${federation}_${key}`,
    to: `CORE_FEDERATIONS_${federation}_${key}`,
    path: `core.federations.${name}.${path}`,
}));
