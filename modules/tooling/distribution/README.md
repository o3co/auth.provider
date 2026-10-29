# distribution

## Responsibilities
- Forms one distribution bundle per concern directory, whose members are the packages placed in it.
- Derives the dependencies between bundles from their members' runtime dependencies.
- Checks the bundles: each has a manifest, none depends on itself through others, and a shipped bundle depends on no unshipped one.
- Names each bundle, and writes its manifest and its members' built files under that name; writes the index and the entrances its manifest declares.

## Not here
- Lists of module names, bundle names or unshipped bundles, and declared dependencies between bundles.
- Module contents and contracts. A list of published names or versions: a bundle is named `@o3co/auth-provider-<concern directory>`, at the workspace's one version.

## Offers
- `pnpm distribution`: prints each problem and exits 1, or prints `distribution: ok`.
- `pnpm bundles`: builds each shipped bundle into `dist/bundles/<concern directory>` at the workspace's `version`: its members compiled to JS and declarations (tests and test tools, a trial file among them, left out), named publicly, with their other files, and its manifest. Prints each problem and exits 1, or how many it built.
- `pnpm release:pack`, `pnpm release:published` and `pnpm release:check`: packing the release with its index sealed, checking it before anything is published, and checking it as an operator meets it; see the internal modules `release` and `release-check`.
- `pnpm release:evidence-fetch <fetched>` and `pnpm release:evidence-judge <fetched> <dir>`: before anything is published, the evidence of the CI run that tested the tag's tree, fetched with a token and judged without one, or the release stopped; see the internal module `release-evidence`.
- `pnpm release:sbom <tarballs> <dir>`: before anything is published, the release's lists of what it ships, made from its tarballs; see the internal module `release-sbom`.
- `pnpm release:listed <tarballs> <tarballs.json>`: where the release publishes, the tarballs held to those the lists were made of; see the internal module `release-listed`.
- `pnpm release:notes <version> <file>`: where the release publishes, its notes from the version's section of the changelog; see the internal module `release-notes`.

## Invariants
- Bundles come only from the directory structure and the bundle manifests.
- A bundle and an entrance carry the workspace's `license` and `engines` in their manifest, and its `LICENSE` file beside it, so npm and pnpm alike ship it.
- A bundle's and an entrance's manifest carry the description its declaration states, and the workspace's `keywords` followed by its own, each once; a shipped bundle or an entrance without a description is refused.
- Their manifest names the workspace's `repository` (a bundle's with its `modules/<concern directory>`), for provenance; a README beside it points there and ends with the root README's copyright line.
- Dependencies between members of one bundle, and on packages outside the workspace, are no bundle dependencies.
- A missing or unreadable manifest is reported as missing, and only once.
- A cycle is reported along its path, from the first bundle it is reached by.
- Module code never names a bundle; a built file names each member as `<bundle's public name>/<member's directory>[/<entry>]`, and a declaration's own imports point at built `.js` files.
- A shipped member depending on a test runner (`vitest` or a `@vitest/` package) refuses the build: an app would install it. A test builder takes it as an optional peer.
- A bundle depends on other bundles at its own version, and on an outside package at the one version its members state; two versions refuse it. Members' peers are offered as each states them, optional where its `peerDependenciesMeta` says so (a test builder's).
- An outside package a member requires as a peer is a required peer, in that range, of every bundle depending on it, not a dependency: the app then holds the one copy the public types name, where a bundle's own copy beside the app's would make two types of one name and fail the app's type check.

## Depends on
- `create-app` (its patterns, for the release check), `trial` (the layer the release check boots each image on), `combinations` (the features that opt in, for the release's lists); it asks pnpm for the workspace packages, reads their manifests, and compiles with TypeScript; the release check builds and runs images with Docker. Sealing reads the lockfile with `yaml` and tarballs with `tar`; the publish check asks the registry with `npm view`.

## Vocabulary
- bundle: the distribution unit of one concern directory.
- concern directory: the parent directory of the packages the workspace definition places.
- bundle manifest: the `package.json` directly in the concern directory; `"private": false` ships the bundle, `description` and `keywords` say what it is on the registry, `index` asks for the index at a path in it, and `entrances` declares packages of their own name, each a command (`bin`) that calls the `run` of a member (`runs`) with its arguments, its answer the exit status, and its own `description` and `keywords`.
- index: every shipped member's manifest as written, its public package and entry, its section's example (`config.example`), whether it ships its section's defaults (`reference.conf`), and whether its card has a `## Deployment` section, with the release's version and repository, for a module that composes them from a bundle; sealed, the other bundles' and zod's integrity too.
