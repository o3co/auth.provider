# declared

Internal module of `create-app`: what a package's manifest declares for the generated project, read into what `app-output` takes.

## Responsibilities
- Reads a manifest's declarations for the guide (`asks`, `adapts`, `registersAs`) into `Asked`, and of entry samples (`takesSamples`, `sampleOf`, with the sample's text) into `Sampled`.

## Not here
- Where the manifest comes from (the workspace, or a bundle's index as written): `create-app`'s own.
- What each declaration means, and how it is rendered: each module's own, and `app-output`'s.

## Offers
- `askedIn(name, manifest)` → `Asked`; `sampledIn(name, manifest, sample)` → `Sampled`.

## Invariants
- A declaration is taken as the manifest writes it: a field of another type is read as absent, and nothing is added.

## Depends on
- `app-output`, for the types of what it takes.
