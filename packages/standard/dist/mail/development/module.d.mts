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
import { type Module } from "@o3co/auth-provider-core";
export interface StandardDevelopmentMailSenderModuleOptions {
    /**
     * The name the deployment selected its configuration by — the standalone
     * template passes `CONFIG_ENV || NODE_ENV || "development"`.
     */
    readonly environment: string;
}
/** The development sender's module, for the environment the configuration was selected by. */
export declare function standardDevelopmentMailSenderModule(options: StandardDevelopmentMailSenderModuleOptions): Module;
//# sourceMappingURL=module.d.mts.map