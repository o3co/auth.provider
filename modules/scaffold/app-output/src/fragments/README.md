# fragments

## Responsibilities
- Reads each module's fragment (its section's example, `config.example` beside its package.json) as data.
- Maps each fragment's keys to the environment and the local layer: the configuration file reading them, and the environment's and the local layer's examples.

## Not here
- What each module's configuration means, and its fragment: each module's.
- Which fragments a project has, and writing its files: `app-output`.

## Offers
- `fragmentsIn` (directories): the fragments beside the packages there, in that order; a package without one is skipped. `fragmentsOf` (texts, each with where it is from): the same from texts. `fragmentFile` names the file.
- `settingsOf`: each scalar key with the environment variable it reads, and its placeholder; `envName`, a dotted key's variable.
- `writtenOf`: the keys the operator writes in the local layer (lists, values spanning sections, values of several lines).
- `applicationConf`, `envExample`, `localConfExample`: the configuration file and the two examples.
- `sampleFile` names a type's entry sample; `Sampled`, what a package declares of entry samples: the maps it takes them for, each by a contract (`takes`), or the contract its own sample's type is of (`sampleOf`), with the sample's text; `sampleLines`, the samples of the types composed as the local layer's example writes them.

## Invariants
- A fragment holds exactly one section, and no section has two fragments; either is refused, naming the fragment.
- A fragment is read as data: a substitution or an include in it, a backtick or a control character other than a line break in a key or a value, a text over 64 KiB, or keys and values over 32 KiB together, are refused, naming the fragment; nothing is read from the environment or a file.
- An include is refused in words no missing file's error has, so the HOCON library never skips it as a missing file.
- The configuration file reads the fragments' scalar keys from env only, holding no values; each variable is the section and key path joined by `_`, upper-cased, `-` as `_`.
- Two keys reading one variable, or a key no variable can name, are refused, naming both or it.
- Neither example holds a live value line: the local layer's holds each fragment list with its placeholders and each value spanning sections (`audit.receivers`), the environment's each variable, all as comments; a copy sets nothing. A value spanning sections never goes to env.
- A key the local layer's example writes keeps its path: an element HOCON would read otherwise (a quoted key with a dot) is quoted, so the copy reads back one key.
- A scalar given in several lines is still read from env, but left out of the env example and listed among the keys written in the local layer.
- An entry sample is read as a fragment is, and holds one entry's keys, its `type` among them, a second of one type for a map refused; it is written as comments, under the map whose owner takes samples of its type, in the local layer's example alone, never read from the environment nor written to the configuration file. A map no composed sample is for gets none.

## Depends on
- The HOCON library; nothing in the workspace.

## Vocabulary
- fragment: a module's example of its section, placeholders only; a secret's is `REPLACE-…` text its section refuses.
- local layer: the operator's configuration file layered first, for lists and values the environment does not carry.
- entry sample: an entry type's example of one entry of a map, placeholders only, given by the type's package.
