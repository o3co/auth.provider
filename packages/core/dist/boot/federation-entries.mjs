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
import { operatorPath } from "../config/composed.mjs";
import { enabledFederationsOf, FEDERATION_ENTRY_CORE_KEYS, federationNameProblem, } from "../federations/configured.mjs";
import { failureSummary } from "./failure-summary.mjs";
import { frozenSection, parseSection } from "./parsed-values.mjs";
import { BootError } from "./types.mjs";
/**
 * What each `federationTypes` declaration was read as, once, at stage 1,
 * keyed by the registration `federationTypeRegistration` answered for it.
 * The shape check and the parse read these, and the registration closes over
 * the same values, so what is checked is what registers, and a declaration
 * changed afterwards changes none of it.
 */
const snapshots = new WeakMap();
/**
 * The registration a `federationTypes` declaration contributes through: its
 * members read once, here, and a factory of the deps stage 4 hands every
 * contribution that answers a `RegisteredFederationType`, each factory bound
 * to those deps and called as the method it was declared as.
 */
export function federationTypeRegistration(declaration) {
    const { entrySchema, factory, redirectPolicy } = declaration;
    const register = (deps) => Object.freeze({
        entrySchema: entrySchema,
        create: (instance) => factory.call(declaration, deps, instance),
        redirectPolicy: (instance) => redirectPolicy.call(declaration, deps, instance),
    });
    snapshots.set(register, { entrySchema, factory, redirectPolicy });
    return register;
}
/** What a `federationTypes` entry's registration read its declaration as; `undefined` for anything else. */
export function federationTypeSnapshot(registration) {
    return typeof registration === "function" ? snapshots.get(registration) : undefined;
}
/**
 * The types the modules register, in module order: each with its overriding
 * module's declaration, or else its contributing module's. Read after the
 * rows that hold the declarations' shapes, duplicates and override targets.
 */
function declaredTypes(modules) {
    const types = new Map();
    for (const channel of ["contributesEntries", "overridesEntries"]) {
        for (const m of modules) {
            for (const entry of m[channel]) {
                if (entry.kind !== "federationTypes" || typeof entry.key !== "string")
                    continue;
                const snapshot = federationTypeSnapshot(entry.factory);
                if (snapshot !== undefined)
                    types.set(entry.key, { module: m.name, snapshot });
            }
        }
    }
    return types;
}
/**
 * The `type` an entry names. Core's schema holds every entry to a non-empty
 * string before any row reads it; `""`, which no module registers, stands in
 * for anything else.
 */
const typeOf = (entry) => {
    const type = entry.type;
    return typeof type === "string" ? type : "";
};
/** A list of names as JSON strings, so a name with a space or a quote in it reads as written. */
const quoted = (names) => `[${names.map((name) => JSON.stringify(name)).join(", ")}]`;
/** A key that reads as itself in a path: no `.`, quote, space or control character. */
const BARE_KEY = /^[A-Za-z0-9_-]+$/;
/**
 * Where an entry is written, as the operator writes the path: the name bare
 * when it is a bare key, and otherwise quoted as JSON, so a name with a dot,
 * a quote or a newline in it reads as one key on one line.
 */
const entryAt = (name) => `core.federations.${BARE_KEY.test(name) ? name : JSON.stringify(name)}`;
/**
 * Every enabled `core.federations` entry is handled by the installed module
 * that registers its `type` under `federationTypes`; nothing else registers
 * a federation, since no module contributes and no host supplies the
 * `federations` or `federationRedirectPolicies` collector
 * (`contribution-kind-guarded`). An enabled entry whose type no module
 * registers is `federation-type-unhandled`, every such entry listed at once
 * with its type, and the types handled. The message names each entry and its
 * type, and quotes nothing else of it. A disabled entry is not read; that
 * every entry names a type is core's schema's.
 * @internal
 */
export function checkFederationEntriesHandled(modules, config) {
    const types = declaredTypes(modules);
    const unhandled = [];
    for (const [name, entry] of enabledFederationsOf(config)) {
        const type = typeOf(entry);
        if (!types.has(type))
            unhandled.push({ federationName: name, type });
    }
    if (unhandled.length > 0) {
        const handled = [...types.keys()];
        const fixes = unhandled.map(({ federationName, type }) => {
            const at = entryAt(federationName);
            return `${at} names the type ${JSON.stringify(type)}: install the module that contributes federationTypes[${JSON.stringify(type)}], correct the type to one an installed module handles, or set ${at}.enabled = false`;
        });
        throw new BootError({
            message: `${unhandled.length === 1 ? "An enabled federation is" : `${unhandled.length} enabled federations are`} ` +
                `handled by no installed module, and would answer 404: ${fixes.join("; ")}. ` +
                `The installed modules handle the types ${quoted(handled)}.`,
            reason: "federation-type-unhandled",
            stage: "validateManifests",
            details: { reason: "federation-type-unhandled", unhandled, handled },
        });
    }
}
/** An entry without the keys core owns: what its type's schema reads. */
const typeKeysOf = (entry) => Object.fromEntries(Object.entries(entry).filter(([key]) => !FEDERATION_ENTRY_CORE_KEYS.includes(key)));
/**
 * Whether `entry` holds an object under the key its type is named by: the
 * shape of an entry whose type's keys are nested, where a dispatched entry is
 * flat.
 */
const nestsUnderType = (entry, type) => {
    if (!Object.hasOwn(entry, type))
        return false;
    const nested = entry[type];
    return typeof nested === "object" && nested !== null;
};
/** What a refusal adds when `entry` nests its type's keys under its type. */
const flatHint = (entry, type) => nestsUnderType(entry, type)
    ? `; a dispatched entry is flat: the keys nested under ${JSON.stringify(type)} are not read, so write them beside its type`
    : "";
/** Whether `issue` is a schema's refusal of the key `key` as unrecognized. */
const refusesKey = (issue, key) => issue.code === "unrecognized_keys" && issue.path.length === 0 && issue.keys.includes(key);
/**
 * Parses each enabled `core.federations` entry whose `type` a module
 * registers, in the configuration's key order: its name held to the
 * federation-name rule, its `callbackURL` a non-empty string, and the rest of
 * it — the keys core owns removed — parsed synchronously by the type's
 * `entrySchema` as stage 1 read it, then copied and frozen. Answers what
 * stage 4 dispatches. Any refusal makes one `config-validation-failed`
 * naming every issue at the path the operator wrote
 * (`core.federations.<name>…`), each refused entry listed with the module
 * whose declaration of its type is in force and its path; a schema that
 * throws, or answers a value that throws as it is copied, is an issue at the
 * entry. Two such entries never share a `callbackURL`: the callback answers
 * only the federation its path names, so only one of the two could complete
 * a login. Each entry after the first that carries one is an issue at its
 * `callbackURL`, naming the first; the values are compared as written, and
 * the message quotes none of them. An entry is flat: a key named after its
 * type is read as one of the type's keys, and the refusal of a missing
 * `callbackURL`, or a type's schema's refusal of that key as unrecognized,
 * says so when that key holds an object. Runs after
 * `checkFederationEntriesHandled`, so every enabled entry's type is
 * registered.
 * @internal
 */
export function parseFederationEntries(modules, config) {
    const types = declaredTypes(modules);
    const dispatched = [];
    const issues = [];
    // Each issue as the message names it, its entry's name written by `entryAt`.
    const named = [];
    const refused = [];
    // Each callbackURL a dispatched entry carries, with the first entry that carries it.
    const byCallbackURL = new Map();
    for (const [name, entry] of enabledFederationsOf(config)) {
        const type = typeOf(entry);
        const declared = types.get(type);
        if (declared === undefined)
            continue;
        const at = ["core", "federations", name];
        const found = issues.length;
        const issue = (path, message, extra = {}) => {
            issues.push({ code: "custom", ...extra, path: [...at, ...path], message });
            named.push(`${[entryAt(name), ...path.map(String)].join(".")}: ${message}`);
        };
        const nameProblem = federationNameProblem(name);
        if (nameProblem !== undefined)
            issue([], nameProblem);
        const callbackURL = entry.callbackURL;
        if (typeof callbackURL !== "string" || callbackURL.length === 0) {
            issue(["callbackURL"], "an enabled federation's callbackURL is required: the URL its upstream redirects back to" +
                flatHint(entry, type));
        }
        else {
            const other = byCallbackURL.get(callbackURL);
            if (other === undefined)
                byCallbackURL.set(callbackURL, name);
            else {
                issue(["callbackURL"], `an enabled federation's callbackURL is its own, and ${entryAt(other)} has the same one: the callback answers only the federation its path names, so only one of the two could complete a login; give each enabled federation its own callbackURL, or set one of them enabled = false`);
            }
        }
        const result = parseSection(declared.snapshot.entrySchema, typeKeysOf(entry), `the entry schema of the type ${JSON.stringify(type)}`);
        if ("issues" in result) {
            for (const schemaIssue of result.issues) {
                const { path, message, ...extra } = schemaIssue;
                issue(path, refusesKey(schemaIssue, type) ? message + flatHint(entry, type) : message, extra);
            }
        }
        let parsed;
        if ("data" in result) {
            try {
                parsed = frozenSection(result.data);
            }
            catch (thrown) {
                issue([], `the entry the schema of the type ${JSON.stringify(type)} answered threw as it was copied: ${failureSummary(thrown)}`);
            }
        }
        if (issues.length > found || !("data" in result)) {
            refused.push({ module: declared.module, schemaPath: operatorPath(at) });
            continue;
        }
        dispatched.push({
            type,
            module: declared.module,
            instance: Object.freeze({ name, callbackURL: callbackURL, entry: parsed }),
        });
    }
    if (issues.length > 0) {
        throw new BootError({
            message: `Config validation failed — ${issues.length} issue(s) found in core.federations: ${named.join("; ")}.`,
            reason: "config-validation-failed",
            stage: "validateManifests",
            details: { reason: "config-validation-failed", issues, modules: refused },
        });
    }
    return dispatched;
}
/**
 * Builds the provider and the redirect policy of one dispatched entry with
 * its type's registered factories, the provider first. Throws — for the
 * caller to report as the contribution's failure — when a factory throws,
 * when the provider is not an object named after its entry
 * (`namedProvider`), or when the policy is not an object. Registers nothing:
 * the caller registers both, or neither.
 * @internal
 */
export async function buildDispatchedFederation(federation, types) {
    const { instance } = federation;
    const registered = types?.get(federation.type);
    if (registered === undefined) {
        throw new Error(`invariant violated: the type ${JSON.stringify(federation.type)} stage 1 dispatched ${JSON.stringify(instance.name)} to is not registered`);
    }
    const subject = `the type ${JSON.stringify(federation.type)}'s`;
    const provider = namedProvider(await registered.create(instance), instance.name, `${subject} factory`, `its entry, ${JSON.stringify(instance.name)}`);
    const redirectPolicy = await registered.redirectPolicy(instance);
    if (typeof redirectPolicy !== "object" || redirectPolicy === null) {
        throw new RangeError(`${subject} redirectPolicy must answer a redirect policy, an object`);
    }
    return { provider, redirectPolicy };
}
/**
 * `provider` when it is an object whose `name` is `name`, or a `RangeError`:
 * the session finds a federation's redirect policy and callback URL by its
 * provider's name, so a provider registered under another name would be
 * served there with another federation's. `subject` is what answered the
 * provider and `namedAfter` what its name must be, as the message says them.
 * The provider's name is read once and quoted only as JSON, and only when it
 * is a string; nothing else of the provider is quoted.
 */
function namedProvider(provider, name, subject, namedAfter) {
    if (typeof provider !== "object" || provider === null) {
        throw new RangeError(`${subject} must answer a provider, an object`);
    }
    const answered = provider.name;
    if (answered !== name) {
        const named = typeof answered === "string"
            ? `named ${JSON.stringify(answered)}`
            : answered === undefined
                ? "without a name"
                : "whose name is not a string";
        throw new RangeError(`${subject} must answer a provider named after ${namedAfter} (it answered one ${named}): its redirect policy and callback URL are found by that name`);
    }
    return provider;
}
