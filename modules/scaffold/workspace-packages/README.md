# workspace-packages

## Responsibilities
- Lists the packages a workspace's definition places, each by name and directory: the one place a workspace is listed, for generating from it, its local layer and the checks over it.

## Not here
- What a package holds, its manifest or its sources: the caller reads them.
- Resolving dependencies between packages: pnpm.

## Offers
- `workspacePackages(root)` → `WorkspacePackage[]` (`name`, `dir`): the packages `root`'s `pnpm-workspace.yaml` places, the root left out, in order of directory, each directory a real path.

## Invariants
- Read here only where every pattern is whole names and one-level `*`, each perhaps negated: a `*` takes every directory but a hidden one and `node_modules`, a directory counts only with a `package.json` naming it, and a negation leaves out what it reaches wherever it stands.
- Any other definition (another glob, no `packages`, no `pnpm-workspace.yaml`, a package with no name, a `package.json` it cannot read) is listed or refused as `pnpm ls -r` does it, its answer taken as is, so no workspace is refused or listed otherwise than pnpm would.

## Depends on
- `yaml`; pnpm, for a definition it does not read itself.
