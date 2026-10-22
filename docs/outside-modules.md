# Packages outside the release

The module cards are the source of truth. Where this page and a card disagree, the card wins. This page orders the steps and points to the cards.

A package outside the release is a module you publish yourself, as an npm package of your own, and have the generator compose beside the release's modules. The first half of this page is for whoever writes such a package; the second, for whoever generates an app with one.

## Writing a package outside the release

### Declare it

The generator reads what your package is from one key of its `package.json`, `authProvider`:

```json
{
	"name": "@example/did-grant",
	"version": "1.2.0",
	"type": "module",
	"exports": { "./module": "./dist/module.js" },
	"peerDependencies": {
		"@o3co/auth-provider-foundation": "^0.19.0",
		"@o3co/auth-provider-oauth": "^0.19.0",
		"zod": "^4.6.0"
	},
	"authProvider": {
		"format": 1,
		"kind": "feature",
		"needs": ["@mod/tokens", "@mod/clients"]
	}
}
```

- `format` is `1`. A key the generator does not read is refused, and so is a value of the wrong shape.
- `kind` is what your module is: a feature, an adapter of an axis, or a wiring of a feature of your own. Every kind takes `needs`; beside it, a feature takes `optIn` and `joins`, an adapter `replaces` or `adapts` one axis owner (never both), `default` and `joins`, and a wiring `wires`, the name of one of your features composed with it. The `combinations` card says what each field means, and what `combinationsWith` refuses.
- `needs` names the modules your module needs to run, each a module of the release or another package outside it composed with yours. It may point only the way the kinds allow: a feature never needs a capability, an adapter or a wiring, nor a package declared for wirings alone. Your npm dependencies do not go here.
- An adapter declares no default for an axis the release owns: whoever generates the app chooses it, with `--axis`.

### Export the module

Export the module the app imports at `./module`, as every module of the release does. The generator takes it as node's resolver would load it for an app's import: a path inside your package, as in the manifest above, or conditions whose first that applies reaches one. A blocked target (`null`), an array, or a path through `..` or `node_modules` is refused. No code of your package is run to tell.

### Take the release and zod as peers

The kernel finds contracts by the object itself, never by name, and a section's schema errors are told by zod's own class. A second copy of a package of the release, or of zod, breaks both. So:

- Every package of the release you import, and `zod`, is a peer, never optional, and its range holds the release's version (zod's, the app's). The bundle of each module you `needs` is a peer too.
- None of them is among your `dependencies` or `optionalDependencies`, bundled, or reached through an alias (`"my-zod": "npm:zod@…"`).
- Do not bake a copy of them into your build's output: a lockfile cannot show it, and nothing refuses it.

### Run nothing when installed

A package with a `preinstall`, `install` or `postinstall` script is refused.

### Write its section's example

If your module has a section of the configuration, ship its example as `config.example` beside `package.json`, as the release's modules do. It holds exactly one section, whose name no other module composed takes, with placeholders only. It is read as data: a substitution (`${…}`) or an include is refused, and so is a backtick or a control character other than a line break in a key or a value, a file over 64 KiB, or a section over 32 KiB as JSON writes it (its keys and values, with the punctuation and escapes between them). `app-output`'s cards hold these rules.

`README.md` and `reference.conf` beside it are read too, as your card and your section's defaults; a `## Deployment` section of the card is pointed at from the app's guide.

## Composing a package outside the release

### Install it where the generator reads it

The generator touches no registry. Install the package with pnpm into a project of your own, then point the generator at it:

```sh
mkdir outside && cd outside
pnpm init
pnpm add @example/did-grant@1.2.0
cd ..
```

pnpm resolves it from your registry with your credentials and checks its integrity; set `minimumReleaseAge` there too, so a version published a moment ago is not taken. Use pnpm (10 or later, whose default runs no dependency's build script), keep this project on your own machine, put no `overrides` in it, and do not change it while the generator reads it.

### Generate the app

Name the package `npm:<name>`, where you would name a module of the release: among the packages listed, in `--add`, or as an axis's choice. Give the project with `--outside-from`, from the directory holding it. Either list the modules of the app:

```sh
npx @o3co/create-auth-provider@next my-app @mod/tokens npm:@example/did-grant --outside-from outside
```

or add the package to a pattern:

```sh
npx @o3co/create-auth-provider@next my-app --pattern simple-web --add npm:@example/did-grant --outside-from outside
```

The generator takes the version your project's lockfile resolved, and refuses the package where it lies outside the project's `node_modules`, where its manifest or its lockfile entry says other than the other, or where it breaks a rule of the first half of this page; it names every reason at once. A package outside the release is composed beside the published release alone, one recording the integrity of its own packages and of zod: never with `--workspace`. The `create-app` card and its internal module `outside` hold these rules.

The app is installed with no version published within the last day, but the release's own. To take a newer one of your package, name it: `--allow-fresh @example/did-grant` lets that version alone be installed.

### Install the app, and check what it installed

The app records each package outside the release in `outside-modules.json` (its version, its integrity, the dependencies it declares and the registries it comes from), with the integrity the release recorded of each of its own packages and of zod (`held`), and holds its lockfile to that record with `pnpm check:outside`:

```sh
cd my-app
pnpm install
pnpm check:outside
git add pnpm-lock.yaml
```

Commit the lockfile once the check passes. The image runs the same check after installing, and refuses to build otherwise. The check holds what it uses, so nothing of the install it checks is run by it.

`pnpm-workspace.yaml` holds every package of the release the app depends on, or a package outside it takes as a peer, and zod, to one version each. When you upgrade the release, generate the app again with the new release's `create-auth-provider` and take the overrides, `held` and `scripts/check-outside.mjs` from it: the overrides and `held` move together, and the check refuses one without the other. Take the check too, as one older than the record may not read all of it: an app generated before `held` was recorded has a check that does not read it.

## What is and is not checked

Checked: that the app installs each package outside the release as recorded (its version, its integrity, its dependencies as declared, from the registry recorded), that the lockfile holds one version and one resolution of each package of the release and of zod, the tarball whose integrity the release recorded, that each declaration and the graph of all modules keep the rules above, and that generating runs no code of the package and uses no network.

Not checked:

- The code of a package outside the release. It is not part of the release, nor covered by its conformance.
- The project you installed it into. The generator reads it as you left it; a change there between installing and generating, or a change of pnpm's store, reaches the generated app and is not found later by `pnpm check:outside`, which checks the app's install, not what was generated.
- A registry taken over, publishing a bad version with a good integrity: `minimumReleaseAge` only delays it.
