# setting

## Responsibilities
- Gives sections the schemas for keys of time and size, so no module reads those forms itself.

## Not here
- What a key means, its bounds and its default: the section's own schema, which pipes this into a number.

## Offers
- `setting.duration(unit)` (`ms`, `s`, `m`, `h` or `d`) and `setting.size(unit)` (`B` unless told, `KB` to `GiB`): a key written with its unit, read as a number of `unit`.
- A section pipes one into its bounds, and gives a default as an operator writes it: `ttl: setting.duration("s").pipe(z.number().int().min(60)).prefault("5m")`.

## Invariants
- A value must name its unit (`30s`, `"64 KiB"`); a bare number, or a string of one as an environment variable gives, is refused.
- The forms read are the HOCON library's; only this module names the library's markers.

## Depends on
- None (the HOCON library only)
