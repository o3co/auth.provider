# trial

## Responsibilities
- Builds the local layer that boots a generated app for a test or a conformance run, from the trial file of each module the app composes; it holds no module's values.

## Not here
- What a module's trial sets, and its trial file (`trial.conf` beside its package.json): each module's.
- Generating the app: `create-app`.
- A deployment's configuration: the operator's, from the generated examples.

## Offers
- `trialLayer(target, { redisUrl, leave?, layer? })`: the local layer, as HOCON, for the app generated in `target`.
  - It reads the trial file of each module the app's entry imports, whatever names it imports them under, and the kernel's.
  - Each is read after those of what it depends on, then the caller's `layer`, as one HOCON document.
  - The sections in `leave` are dropped; the layer's appends join the trial files' lists.
  - Each mark is made at each call: `TRIAL-FRESH-ED25519-PKCS8-PEM`, `TRIAL-FRESH-32-BYTES-BASE64` and `TRIAL-FRESH-32-BYTES-BASE64URL` fresh, `TRIAL-REDIS-URL` the caller's `redisUrl`.
- `trialFile`: the trial file's name.

## Invariants
- A trial file sets its own section, and only appends (`+=`) to the lists of the sections of what it depends on; any other value is refused, naming the file.
- A package's section is the root of its section's example (`config.example`); a package without one has none of its own.

## Data
- Reads the workspace's package list, and the manifests, trial files and section examples of the packages an app composes; writes nothing.

## Depends on
- The HOCON library, to read the trial files and section examples.

## Vocabulary
- trial file: a module's values that boot it for a test or a conformance run, beside its section's example.
- mark: a value a trial file names for the trial to make, such as a fresh key.
