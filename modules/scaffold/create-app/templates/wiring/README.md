# wiring

The manifest a new wiring starts from: copy `package.json` into `modules/templates/<feature>-store/`, write the feature's name for `<feature>`, and add what the wiring itself imports (such as `zod` for a section). Every wiring in the workspace has this shape. A wiring with a through test, which composes the feature it wires to check the wiring, adds `devDependencies` for what that test composes, and nothing else.
