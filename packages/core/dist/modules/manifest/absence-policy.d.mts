/**
 * The declared-absence vocabulary for optional DI slots (#363).
 *
 * An `optional` key on its own means "absence is indistinguishable from
 * nothing-to-do", and three shipped silent no-ops came from exactly that
 * reading: RFC 7009 revocation with no denylist wired (#277), a
 * subject-revocation watermark nothing consulted (#322), and an audit sink
 * slot left empty so every security event was discarded (#287). Each was a
 * capability that *looked* wired because nothing said otherwise.
 *
 * #277 hand-rolled the fix for one key: refuse boot unless the composition
 * either fills the slot or declares the capability absent in config
 * (`oauth.revocation.accessToken = "unsupported"`). An {@link AbsencePolicy}
 * is that fix as manifest vocabulary — a module attaches one to an optional
 * key, and the stage-1 declared-absence guard (`checkDeclaredAbsence`)
 * enforces it generically: unfilled slot + no declaration → `BootError`
 * (`component-absence-undeclared`), never a silent no-op.
 *
 * The policy is **data, not code** — a config path and the one value that
 * counts as the declaration — so stage 1 stays deterministic and
 * side-effect-free, and the boot error can name the exact line an operator
 * has to write. A policy that needs to *compute* whether absence is declared
 * is a sign the declaration vocabulary is wrong, not that this type needs a
 * callback.
 *
 * #277's bespoke check ("step 13.9") predated this vocabulary and was
 * folded onto it by #375: `ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY` carries its
 * semantics, and its reason merged into `component-absence-undeclared`.
 */
export interface AbsencePolicy {
    /**
     * Path into the parsed application config, one segment per element
     * (`["audit", "sink", "type"]` reads `config.audit.sink.type`). The value
     * at this path is what an operator writes to declare the capability
     * absent on purpose.
     */
    readonly configKey: readonly string[];
    /**
     * The one value at {@link configKey} that counts as the declaration.
     * Compared with `===` against the parsed config — a policy whose
     * declaration needs coercion should point at a schema-validated key
     * instead of teaching this comparison to guess.
     */
    readonly absentValue: string;
    /**
     * Operator-facing sentence appended to the boot error: what the slot
     * does, so the operator deciding between wiring it and declaring it
     * absent knows what the deployment loses. The guard already names the
     * config line; the hint carries the stakes.
     */
    readonly hint: string;
}
//# sourceMappingURL=absence-policy.d.mts.map