/**
 * The template's MFA switch, the composition root's own key `mfaMode`
 * (`MFA_MODE`), `required` unless set otherwise: reading it before the
 * modules are chosen, the modules it installs, and what it hands boot of the
 * MFA module's section. Off installs nothing of MFA and hands boot nothing of
 * it; on installs the MFA package's modules over the two MFA stores
 * `adapters` selects.
 *
 * Refuses, each before boot with a `config-validation-failed` `BootError`
 * (`bootRefusal.mts`) that names the keys and variables and quotes no value
 * of a mode, a timeout or a key:
 * - a switch outside its three values, or a file's `mfaMode` that `MFA_MODE`
 *   contradicts (`readMfaSwitch`);
 * - an MFA store kept in memory with MFA on, unless every environment name
 *   it reads says development or test (`mfaModulesFor`) — the first refusal a
 *   deployment that sets nothing about MFA meets outside development, so it
 *   also names what MFA needs there and `MFA_MODE=off`;
 * - an `mfa.mode` the configuration writes that the switch does not say;
 *   `MFA_ENCRYPTION_KEY` set beside a ring that holds the development sample
 *   key in its place; and `mfa.storeTimeoutMs` below the user directory's
 *   timeout where the Store is called (`mfaSectionForBoot`).
 */
import { type Module } from "@o3co/auth-provider-core";
import { type Adapters, type MfaSwitch } from "./sections.mjs";
/** The composition root's MFA switch, a key of its own. No module may be named after it. */
export declare const MFA_SWITCH = "mfaMode";
/**
 * `mfaMode` from `resolved` — the template's own layers over its
 * `config/reference.conf` — parsed with the template's schema, under `env`,
 * the environment the layers were substituted with. A value the schema
 * refuses, or `MFA_MODE` set to other than what a file writes over it, is a
 * `config-validation-failed` `BootError` naming `mfaMode` and `MFA_MODE`.
 */
export declare function readMfaSwitch(resolved: Readonly<Record<string, unknown>>, env: Readonly<Record<string, string>>): MfaSwitch;
/**
 * The modules the switch installs: none under `off`; otherwise the MFA
 * package's (`mfaModules`, `mfaResetModule`), the session package's
 * `loginCompletionModule`, and the two MFA stores `adapters` selects — on
 * Redis, in the Store over `storeTransport` (the factors only), or in memory.
 * A store in memory loses every factor, lock, hold and recorded email proof
 * at a restart, after which whoever holds a password can bind a factor of
 * their own: it is refused, naming each such setting and its variable,
 * unless `environment`, and `CONFIG_ENV` and `NODE_ENV` where set, each say
 * development or test. Under `core.deployment.mode = "multi"` core refuses
 * the memory stores by name as well.
 */
export declare function mfaModulesFor(options: {
    readonly mode: MfaSwitch;
    readonly adapters: Pick<Adapters, "mfaFactorStore" | "mfaTransactionStore">;
    readonly storeTransport: unknown;
    readonly environment: string | undefined;
}): Module[];
/**
 * What boot is handed of the `mfa` section under the switch `mode`;
 * `undefined` hands none. None unless a loaded module owns it (`owned`):
 * what the configuration writes there — `config/development.conf`'s key ring
 * included — sets nothing while the switch installs no MFA. Owned, it is
 * `resolved`'s section, with `mfa.mode` written from the switch when the
 * switch installs MFA. Refuses (see the file header), whatever the switch, an
 * `mfa.mode` the composition's own layers (`written`, their `mfa`) write that
 * the switch does not say, or an `mfa` written as a value; with MFA on, a
 * ring holding the development sample key while `MFA_ENCRYPTION_KEY` names
 * another, and, where the Store is called (`storeCalled`), `mfa.storeTimeoutMs`
 * below `repositories.user.http.timeout`.
 */
export declare function mfaSectionForBoot(options: {
    readonly mode: MfaSwitch;
    readonly written: unknown;
    readonly resolved: Readonly<Record<string, unknown>>;
    readonly owned: boolean;
    readonly storeCalled: boolean;
    readonly env: Readonly<Record<string, string>>;
}): unknown;
/**
 * `oauth` with `urn:o3co:acr:mfa = ["mfa"]` added to its `acr` table while
 * the switch installs MFA, unless the configuration writes that entry
 * itself; as it is otherwise, so a composition without MFA advertises
 * exactly what it would without the switch.
 */
export declare function oauthForBoot(mode: MfaSwitch, oauth: unknown): unknown;
//# sourceMappingURL=mfaSwitch.d.mts.map