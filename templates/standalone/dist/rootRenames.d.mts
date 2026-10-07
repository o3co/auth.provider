/**
 * A variable renamed with a path of the composition root's own: its old name,
 * its new one, the path the new one binds, and the module that path's section
 * is named after in a refusal's details (`bootRefusal.mts`).
 */
export interface RootRename {
    readonly module: string;
    readonly from: string;
    readonly to: string;
    readonly path: string;
}
/**
 * Refuses, with an `environment-variable-renamed` `BootError`, an old name in
 * `env` set alone (`unset`), or beside its new name (`different`, whatever
 * either holds), in the words core refuses a module's rename in. Every such
 * rename is named at once; no value is compared, quoted or carried.
 */
export declare function refuseRenamedVariables(env: Readonly<Record<string, string>>, renames: readonly RootRename[]): void;
/**
 * The variables `config/application.conf` binds for the two federations the
 * template ships, each renamed after its path under `core.federations`: in
 * core's section, so named under module "core" in a refusal's details.
 */
export declare const SHIPPED_FEDERATION_RENAMES: readonly RootRename[];
//# sourceMappingURL=rootRenames.d.mts.map