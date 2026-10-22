# exported

## Responsibilities
- Tells whether a package's `exports` maps a subpath to a target node would load for an app's import, read as node's resolver reads it, without running the package.

## Not here
- Which subpath an app imports, and what it does when none loads: `outside`.

## Offers
- `loadsSubpath` (exports, subpath): whether the subpath's target loads.

## Invariants
- A path loads where it starts `./` and holds no empty, `.`, `..` or `node_modules` segment, plain or %-encoded; resolved under the package, its path (not its query) holds no encoded separator and decodes.
- Conditions are walked in their order: the first of `node`, `import`, `module-sync`, `node-addons` and `default` that the target names is taken; one none of whose own conditions applies is passed over to the next.
- A null, a refused path, or conditions keyed as an array index (which node refuses whole) do not load; nor does an array, though node may take one.
- Exports mixing subpaths (keys starting `.`) and conditions at the top give nothing: node refuses them whole.

## Depends on
- Nothing.
