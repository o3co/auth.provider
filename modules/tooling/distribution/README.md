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
- `pnpm bundles`: builds each shipped bundle into `dist/bundles/<concern directory>` at the workspace's `version`: its members compiled to JS and declarations (tests and test tools left out), named publicly, with their other files, and its manifest. Prints each problem and exits 1, or how many it built.
- `pnpm release:check`: packs every bundle and entrance, makes an app of each pattern with the packed `create-auth-provider`, installs it from the tarballs alone, type-checks it, and boots it to `/readyz` or to its refusals, each told. Exits 1 on any problem.

## Invariants
- The release check refuses a tarball without its `LICENSE`.
- The release check boots each app in the image its Dockerfile builds; only the `deps` stage is replaced, by the same `--prod` install from the tarballs in the `base` stage, as the registry has none of them yet.
- Without Docker, the release check exits 1 at once: no boot is skipped.
- Bundles come only from the directory structure and the bundle manifests.
- A bundle and an entrance carry the workspace's `license` and `engines` in their manifest, and its `LICENSE` file beside it, so npm and pnpm alike ship it.
- A bundle's and an entrance's manifest carry the description its declaration states, and the workspace's `keywords` followed by its own, each once; a shipped bundle or an entrance without a description is refused.
- Their manifest names the workspace's `repository` (a bundle's with its `modules/<concern directory>`), for provenance; a README beside it points there and ends with the root README's copyright line.
- Dependencies between members of one bundle, and on packages outside the workspace, are no bundle dependencies.
- A missing or unreadable manifest is reported as missing, and only once.
- A cycle is reported along its path, from the first bundle it is reached by.
- Module code never names a bundle; a built file names each member as `<bundle's public name>/<member's directory>[/<entry>]`, and a declaration's own imports point at built `.js` files.
- A bundle depends on other bundles at its own version, and on an outside package at the one version its members state; two versions refuse it. Members' peers are optional, as only test builders read them.

## Depends on
- `create-app` (its patterns and trial settings, for the release check); it asks pnpm for the workspace packages, reads their manifests, and compiles with TypeScript; the release check builds and runs images with Docker.

## Vocabulary
- bundle: the distribution unit of one concern directory.
- concern directory: the parent directory of the packages the workspace definition places.
- bundle manifest: the `package.json` directly in the concern directory; `"private": false` ships the bundle, `description` and `keywords` say what it is on the registry, `index` asks for the index at a path in it, and `entrances` declares packages of their own name, each a command (`bin`) that calls the `run` of a member (`runs`) with its arguments, its answer the exit status, and its own `description` and `keywords`.
- index: every shipped member's manifest as written, its public package and entry, and its section's example (`config.example`), for a module that composes them from a bundle.
