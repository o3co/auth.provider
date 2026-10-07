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
import { isWellFormedErrorCode } from "../errors/envelope.mjs";
import { FEDERATED_AMR, PASSWORD_AMR } from "../grants/authenticationClaims.mjs";
import { SECOND_FACTOR_AMR } from "./acr.mjs";
/**
 * The stores admission reads itself, by the name an `unavailable` admission
 * gives each one's outage. Every other `Admission.store` is a requirement's
 * name, so no requirement may register under one of these: a consumer that
 * tells an outage by its store never takes a requirement's for a store's.
 */
export const ADMISSION_INFRASTRUCTURE_STORES = Object.freeze([
    "user_session",
    "revocation_boundary",
    "session_lifecycle",
]);
/** Whether `store` names one of admission's own stores — else it is a requirement's name. */
export const isAdmissionInfrastructureStore = (store) => ADMISSION_INFRASTRUCTURE_STORES.includes(store);
/** How each of admission's own stores is described when it could not answer: the revocation boundary's in the words the token side uses for it. */
const INFRASTRUCTURE_OUTAGES = {
    user_session: "session store unavailable",
    revocation_boundary: "revocation store unavailable",
    session_lifecycle: "session lifecycle store unavailable",
};
/**
 * What an `unavailable` admission is described as to the client: either of
 * admission's own stores by name, anything else as a requirement's outage,
 * never by the requirement's name (that is the operator's, for the log
 * line). One text for every consumer.
 */
export const describeAdmissionOutage = (store) => isAdmissionInfrastructureStore(store)
    ? INFRASTRUCTURE_OUTAGES[store]
    : "session requirement unavailable";
/** The parameter a consumer adds to the page itself, on the way to it: never a page's own. */
const RESERVED_PAGE_PARAM = "redirect_to";
const isPlainObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
/** Whether a page's `url` carries what it may not: a backslash (a browser reads it as a slash), an encoded one, or a control character. */
const forbiddenInPageUrl = (url) => /[\\]|%5c/i.test(url) ||
    Array.from(url, (char) => char.charCodeAt(0)).some((code) => code < 0x20 || code === 0x7f);
/** The origin a path is resolved against when no issuer is given: any path must keep it. */
const PATH_ORIGIN = "https://issuer.invalid";
/**
 * `page` as a requirement may declare it: `url` a path that stays on the
 * issuer's origin once resolved as a browser resolves a `Location` (not
 * `//host` or `/\host`), or an absolute `http(s)` URL on `issuer`'s origin
 * (any origin when no issuer is given); never a backslash, an encoded one or
 * a control character; `params` strings, without `redirect_to`. Answers a
 * frozen copy; anything else is a `RangeError` naming what is wrong.
 */
export function checkStepUpPage(page, issuer) {
    if (!isPlainObject(page))
        throw new RangeError("stepUpPage must be an object");
    const url = page.url;
    if (typeof url !== "string" || url.length === 0) {
        throw new RangeError("stepUpPage.url must be a non-empty string");
    }
    if (forbiddenInPageUrl(url)) {
        throw new RangeError("stepUpPage.url must not carry a backslash, an encoded backslash or a control character");
    }
    let resolved;
    if (url.startsWith("/")) {
        const base = new URL(issuer ?? PATH_ORIGIN);
        // A path free of backslashes and control characters always resolves
        // against a base; what it may do is leave the base's origin.
        resolved = new URL(url, base);
        if (resolved.origin !== base.origin) {
            throw new RangeError("stepUpPage.url must stay on the issuer's origin once resolved: a path, not a scheme-relative URL");
        }
    }
    else {
        try {
            resolved = new URL(url);
        }
        catch {
            throw new RangeError("stepUpPage.url must be a path or an absolute URL");
        }
        if (resolved.protocol !== "https:" && resolved.protocol !== "http:") {
            throw new RangeError("stepUpPage.url must be an http or https URL");
        }
        if (issuer !== undefined && resolved.origin !== new URL(issuer).origin) {
            throw new RangeError("stepUpPage.url must be on the issuer's origin");
        }
    }
    if (resolved.searchParams.has(RESERVED_PAGE_PARAM)) {
        throw new RangeError(`stepUpPage.url must not carry ${RESERVED_PAGE_PARAM} in its query: it is the consumer's return parameter`);
    }
    // The params: read once, copied from their own enumerable string keys
    // into a plain object that is what gets validated — a Proxy that answers
    // one thing to a probe and another to a read cannot get past.
    const paramsRead = page.params;
    if (!isPlainObject(paramsRead))
        throw new RangeError("stepUpPage.params must be an object");
    const params = {};
    for (const key of Object.keys(paramsRead))
        params[key] = paramsRead[key];
    // Every own key must be in the copy: a symbol, a non-enumerable key, or one
    // a Proxy lists but hides from the copy is refused.
    for (const key of Reflect.ownKeys(paramsRead)) {
        if (typeof key !== "string" || !Object.hasOwn(params, key)) {
            throw new RangeError(`stepUpPage.params.${String(key)} is not an enumerable string key the copy could read: params must be a plain object`);
        }
    }
    if (Object.hasOwn(params, RESERVED_PAGE_PARAM)) {
        throw new RangeError(`stepUpPage.params must not carry ${RESERVED_PAGE_PARAM}: it is the consumer's return parameter`);
    }
    for (const [key, value] of Object.entries(params)) {
        if (typeof value !== "string") {
            throw new RangeError(`stepUpPage.params.${key} must be a string`);
        }
    }
    return Object.freeze({ url, params: Object.freeze(params) });
}
/**
 * The step-up page as a browser is sent to it: `page.url` resolved on
 * `issuer`, each param set on the query (`searchParams.set`, never
 * concatenation), as one absolute URL. Registration computes it once, as the
 * registered page's `href`. No return parameter is added: `/authorize` sets
 * its own on the `href`, and a JSON consumer answers it as it is.
 * @internal
 */
export function stepUpPageUrl(page, issuer) {
    const url = new URL(page.url, issuer);
    for (const [name, value] of Object.entries(page.params))
        url.searchParams.set(name, value);
    return url.href;
}
const isNonEmptyString = (value) => typeof value === "string" && value.length > 0;
const isNameList = (value) => Array.isArray(value) && value.every(isNonEmptyString);
/** A hint's key: a short lower-case identifier. */
const HINT_KEY = /^[a-z][a-z0-9_]{0,31}$/;
/** A hint's value: an enum-like token. A snapshot, a URL, an address or a name cannot take this form. */
const HINT_TOKEN = /^[a-z][a-z0-9_-]{0,63}$/;
/** The hint keys core reserves: what a page must never be told under any name. */
const RESERVED_HINT_KEYS = new Set([
    "user",
    "sub",
    "sid",
    "subject",
    "email",
    "mail",
    "address",
    "phone",
    "name",
    "token",
    "secret",
    "password",
    "claims",
    "profile",
]);
/** Whether `key` may name a hint: the identifier form, and not a reserved name. */
export const isHintKey = (key) => typeof key === "string" && HINT_KEY.test(key) && !RESERVED_HINT_KEYS.has(key);
/** Whether `value` may be one hint's text: an enum-like token. */
export const isHintToken = (value) => typeof value === "string" && HINT_TOKEN.test(value);
// ---------------------------------------------------------------------------
// The remediations
// ---------------------------------------------------------------------------
/** A remediation's route, after the requirement's own name and a dot: a lower-case identifier. */
const REMEDIATION_ROUTE = /^[a-z][a-z0-9_]*$/;
/**
 * `remediations` as a requirement may declare them: each `<name>.<route>`,
 * declared once. Another requirement's name is impossible by construction:
 * the route holds no dot, and the kind refuses a second requirement of one
 * name. A registered action's name is refused once both kinds have registered
 * (`checkRemediationsAgainstActions`).
 */
function checkRemediations(name, value, refuse) {
    if (!isNameList(value))
        refuse("remediations must be a list of names");
    const prefix = `${name}.`;
    const seen = new Set();
    for (const remediation of value) {
        const route = remediation.startsWith(prefix) ? remediation.slice(prefix.length) : undefined;
        if (route === undefined || !REMEDIATION_ROUTE.test(route)) {
            refuse(`remediation "${remediation}" is not a route of this requirement's own: a remediation is named "${prefix}<route>", the route a lower-case identifier`);
        }
        if (seen.has(remediation))
            refuse(`remediation "${remediation}" is declared twice`);
        seen.add(remediation);
    }
}
/** Whether `value` is an iterable that is not a string: what a reach may be given as. */
const isIterableOfValues = (value) => typeof value === "object" &&
    value !== null &&
    typeof value[Symbol.iterator] === "function";
/** The copies `registeredRequirement` made: what `sealRegisteredReach` seals. */
const registeredCopies = new WeakSet();
/**
 * Whether `value` is a copy `registeredRequirement` made — never the object
 * a factory returned, nor a copy of a registered one.
 * @internal
 */
export const isRegisteredRequirement = (value) => typeof value === "object" && value !== null && registeredCopies.has(value);
/** Each registered copy's sealed reach: read once at the end of boot's stage 4, answered afterwards. */
const sealedReach = new WeakMap();
/**
 * A sealed reach: a read-only view over a private set — `has`, `size` and
 * iteration, no `add` or `delete` at all. Not a frozen native `Set`, which
 * still accepts both.
 */
class SealedReach {
    #values;
    constructor(values) {
        this.#values = new Set(values);
        Object.freeze(this);
    }
    get size() {
        return this.#values.size;
    }
    has(value) {
        return this.#values.has(value);
    }
    keys() {
        return this.#values.keys();
    }
    values() {
        return this.#values.values();
    }
    entries() {
        return this.#values.entries();
    }
    forEach(callback, thisArg) {
        for (const value of this.#values)
            callback.call(thisArg, value, value, this);
    }
    [Symbol.iterator]() {
        return this.#values.values();
    }
    get [Symbol.toStringTag]() {
        return "SealedReach";
    }
    // The set algebra `ReadonlySet` declares, each answered over a copy, so
    // nothing hands the private set out.
    union(other) {
        return new Set(this.#values).union(other);
    }
    intersection(other) {
        return new Set(this.#values).intersection(other);
    }
    difference(other) {
        return new Set(this.#values).difference(other);
    }
    symmetricDifference(other) {
        return new Set(this.#values).symmetricDifference(other);
    }
    isSubsetOf(other) {
        return this.#values.isSubsetOf(other);
    }
    isSupersetOf(other) {
        return this.#values.isSupersetOf(other);
    }
    isDisjointFrom(other) {
        return this.#values.isDisjointFrom(other);
    }
}
/** Seals `requirement` on `values` when it is a registered copy, and answers the sealed view. */
function seal(requirement, values) {
    const sealed = new SealedReach(values);
    if (registeredCopies.has(requirement))
        sealedReach.set(requirement, sealed);
    return sealed;
}
/** The remediation actions core issued: the only ones admission keeps the `remediation` grade for. */
const issuedActions = new WeakSet();
/** The issued actions by the ORIGINAL object a factory returned: what `issuedRemediationActions` answers the contributing module. */
const actionsByOriginal = new WeakMap();
/** The issued actions by the registered copy: what admission checks a `remediation` action against. */
const actionsByCopy = new WeakMap();
/**
 * The remediation actions core issued to a requirement, keyed by route
 * (`step_up` for `mfa.step_up`), answered to the module that holds the
 * object its factory returned and to nothing else: the resolver hands out
 * the registered copy, which carries none of them, so a consumer holding
 * the resolver cannot obtain a `remediation` action. `undefined` for an
 * object that was never registered, a copy of one, or the registered copy.
 * A requirement object is registered once, and its actions are read in the
 * boot that registered it: registering the same object again (the last
 * registration wins) issues it new ones, which the earlier boot's resolver
 * refuses.
 */
export function issuedRemediationActions(requirement) {
    return typeof requirement === "object" && requirement !== null
        ? actionsByOriginal.get(requirement)
        : undefined;
}
/** The issued actions of a registered copy, for admission's own check. @internal */
export const issuedActionsOf = (copy) => actionsByCopy.get(copy);
/** Whether `action` is one core issued to a registered requirement — never a literal or a copy. */
export const isIssuedAction = (action) => typeof action === "object" && action !== null && issuedActions.has(action);
/**
 * A requirement's page as it is registered: checked (`checkStepUpPage`, on
 * `issuer`'s origin when one is given) and resolved on that issuer, once, to
 * its `href`. A path has nothing to be resolved on without an issuer, and is
 * refused through `refuse`.
 */
function registeredPage(page, issuer, refuse) {
    const checked = checkStepUpPage(page, issuer);
    if (issuer === undefined && checked.url.startsWith("/")) {
        refuse(`stepUpPage.url ${JSON.stringify(checked.url)} is a path, resolved on the issuer: none was given to register it on — boot registers on the oauthTokenSettings slot's issuer, or on oauth.jwt.issuer in a composition without one; a test passes resolverForTests(requirements, { issuer })`);
    }
    return Object.freeze({
        url: checked.url,
        params: checked.params,
        href: stepUpPageUrl(checked, issuer ?? checked.url),
    });
}
/**
 * `value` as it is registered: its shape held to the contract and copied,
 * each field read once, so what the resolver answers at request time is
 * what was registered. `name` must be RFC 6749 error-code characters and
 * not one of admission's own store names; `secondFactorAuthority` is `true`,
 * `false` or absent (read as `false`); `stepUpPage` is checked and resolved
 * once to its `href` on `issuer` (a path page with no issuer is refused);
 * `admit` and `admitPrimary` delegate to the value's.
 *
 * `reach` is NOT read here: it may be a getter over what registers in the
 * same pass (MFA's, over `mfaFactorResolver`). `sealRegisteredReach` reads
 * and seals it at the end of boot's stage 4, so request-time readers see
 * what boot checked; until then the copy answers the value's own. A
 * `RangeError` names what is wrong; the boot planner reports it as the
 * contribution's failure.
 */
export function registeredRequirement(value, issuer) {
    if (!isPlainObject(value))
        throw new RangeError("a session requirement must be an object");
    // Each field is read once, into a local that is what gets validated and
    // copied: a getter answering differently to a second read changes nothing.
    const name = value.name;
    if (!isNonEmptyString(name)) {
        throw new RangeError("a session requirement's name must be a non-empty string");
    }
    // A `step_up` names the requirement on the wire, under RFC 6749's grammar
    // for an error code: a name outside it would be dropped there, and the
    // client left without the remediation. Quoted escaped: it may hold a
    // control character.
    if (!isWellFormedErrorCode(name)) {
        throw new RangeError(`session requirement ${JSON.stringify(name)}: the name must be RFC 6749's error-code characters — printable ASCII without " or \\ — the only ones a step_up is sent in`);
    }
    const refuse = (what) => {
        throw new RangeError(`session requirement "${name}": ${what}`);
    };
    if (isAdmissionInfrastructureStore(name)) {
        refuse(`the name is one admission gives an outage of its own stores (${ADMISSION_INFRASTRUCTURE_STORES.join(", ")}): a consumer telling an outage by its store would take the requirement's for the store's`);
    }
    const declared = value.secondFactorAuthority;
    if (declared !== undefined && typeof declared !== "boolean") {
        refuse("secondFactorAuthority must be true, false or absent");
    }
    // A page that fails names what is wrong itself (`checkStepUpPage`); one
    // that passes is resolved here, once, on the issuer it was checked on.
    const page = value.stepUpPage;
    const stepUpPage = page === undefined ? undefined : registeredPage(page, issuer, refuse);
    const remediationsRead = value.remediations;
    checkRemediations(name, remediationsRead, refuse);
    const hintKeysRead = value.hintKeys;
    if (!isNameList(hintKeysRead) || !hintKeysRead.every(isHintKey)) {
        refuse("hintKeys must be a list of hint names: lower-case identifiers of at most 32 characters, none a name core reserves");
    }
    const admit = value.admit;
    if (typeof admit !== "function")
        refuse("admit must be a function");
    const primaryAsk = value.admitPrimary;
    if (primaryAsk !== undefined && typeof primaryAsk !== "function") {
        refuse("admitPrimary must be a function or absent");
    }
    const source = value;
    const remediations = Object.freeze([...remediationsRead]);
    // The remediation actions, issued here and nowhere else: handed to
    // the contributing module by the object it returned, never on the copy.
    const actions = {};
    for (const remediation of remediations) {
        const issued = Object.freeze({
            name: remediation,
            grade: "remediation",
        });
        issuedActions.add(issued);
        actions[remediation.slice(name.length + 1)] = issued;
    }
    const copy = Object.freeze({
        name,
        secondFactorAuthority: declared === true,
        get reach() {
            return sealedReach.get(copy) ?? source.reach;
        },
        stepUpPage,
        remediations,
        hintKeys: Object.freeze([...hintKeysRead]),
        admit: (input) => admit.call(source, input),
        ...(primaryAsk === undefined
            ? {}
            : {
                admitPrimary: (primary) => primaryAsk.call(source, primary),
            }),
    });
    registeredCopies.add(copy);
    const issued = Object.freeze(actions);
    actionsByOriginal.set(value, issued);
    actionsByCopy.set(copy, issued);
    return copy;
}
/**
 * A registered requirement's `reach`, read once after the name-keyed pass
 * and held to the one home of these rules: an iterable of non-empty strings,
 * no primary's marker (`pwd`, `fed`), a `stepUpPage` when not empty, and a
 * second-factor value or any value at all only from the second-factor
 * authority (only its step-up is ever written into a live session). Boot,
 * `resolverForTests` and the contract suite all run it. Answers a read-only
 * snapshot and seals a registered copy on it; a refused reach is not sealed.
 * `remedy` is appended to the refusal of a non-empty reach from any other.
 */
export function sealRegisteredReach(requirement, remedy) {
    const refuse = (what) => {
        throw new RangeError(`session requirement "${requirement.name}": ${what}`);
    };
    if (!isRegisteredRequirement(requirement)) {
        return refuse("is not a registered copy: its declaration is the one registration read");
    }
    const authority = requirement.secondFactorAuthority;
    const reach = requirement.reach;
    if (!isIterableOfValues(reach))
        return refuse("reach must be a Set of amr values");
    const read = new Set();
    for (const entry of reach) {
        if (!isNonEmptyString(entry))
            refuse("reach holds a value that is not a non-empty string");
        const value = entry;
        if (value === PASSWORD_AMR || value === FEDERATED_AMR) {
            refuse(`reach names "${value}", a primary's marker, which no step-up adds`);
        }
        if (!authority && SECOND_FACTOR_AMR.has(value)) {
            refuse(`reach names "${value}", a second-factor value only the second-factor authority may reach`);
        }
        read.add(value);
    }
    if (read.size > 0 && requirement.stepUpPage === undefined) {
        refuse("a requirement that reaches something must declare where the step-up starts");
    }
    if (read.size > 0 && !authority) {
        refuse(`reaches ${[...read].map((value) => `"${value}"`).join(", ")}: in this release only the second-factor authority adds vouched values to a session, so any other reach must be empty${remedy === undefined ? "" : ` — ${remedy}`}`);
    }
    return seal(requirement, read);
}
/**
 * Seals a registered copy's reach as boot does — read once, a frozen
 * snapshot the copy answers afterwards — without the rule
 * `sealRegisteredReach` holds it to, which the contract suite and boot do.
 * For `resolverForTests` alone.
 * @internal
 */
export function snapshotReach(requirement) {
    const reach = requirement.reach;
    if (!isIterableOfValues(reach)) {
        throw new RangeError(`session requirement "${requirement.name}": reach must be a Set of amr values`);
    }
    return seal(requirement, reach);
}
/** The registered requirements among `requirements` that declare the second-factor authority, in order: at most one may. */
export const secondFactorAuthorities = (requirements) => [...requirements].filter((requirement) => requirement.secondFactorAuthority);
/**
 * Refuses a registered requirement whose remediation is the name of a
 * registered action — `registrant` answers who registered it — naming the
 * registrant: as a remediation it would skip every requirement for that
 * action. Boot and `resolverForTests` run it once both kinds have registered.
 */
export function checkRemediationsAgainstActions(requirement, registrant) {
    for (const remediation of requirement.remediations) {
        const by = registrant(remediation);
        if (by === undefined)
            continue;
        throw new RangeError(`session requirement "${requirement.name}": remediation "${remediation}" is the name of the admission action ${by} registers: as a remediation it would skip every requirement for that action`);
    }
}
