/-!
# Minimal fail-closed evidence admission for Lean federation capsules.

A declaration identity is its logical key plus statement hash. Toolchain and
source provenance belong to attestations, not to statement identity. This lets
the same formal statement acquire independent environment attestations while
rejecting same-key/different-statement replacement.
-/

namespace Qf

inductive Evidence where
  | informal | candidate | formal
  deriving DecidableEq, Repr

inductive Projection where
  | exact | lossy
  deriving DecidableEq, Repr

/-- Only an exact projection preserves FORMAL evidence. -/
def projectEvidence : Projection → Evidence → Evidence
  | .exact, evidence => evidence
  | .lossy, .formal => .candidate
  | .lossy, evidence => evidence

theorem lossy_projection_not_formal (evidence : Evidence) :
    projectEvidence .lossy evidence ≠ .formal := by
  cases evidence <;> decide

structure Declaration where
  logicalKey : String
  statementHash : String
  profileHash : String
  sourceCommit : String
  evidence : Evidence
  deriving DecidableEq, Repr

inductive SyncError where
  | candidateNotFormal | currentNotFormal | keyConflict | statementConflict
  deriving DecidableEq, Repr

/-- Admission is all-or-nothing for a declaration and never rewrites its origin. -/
def admitDeclaration (current? : Option Declaration) (candidate : Declaration) :
    Except SyncError Declaration :=
  if candidate.evidence ≠ .formal then
    .error .candidateNotFormal
  else
    match current? with
    | none => .ok candidate
    | some current =>
      if current.evidence ≠ .formal then
        .error .currentNotFormal
      else if current.logicalKey ≠ candidate.logicalKey then
        .error .keyConflict
      else if current.statementHash ≠ candidate.statementHash then
        .error .statementConflict
      else
        .ok current

theorem admit_informal_rejected (current? : Option Declaration) (candidate : Declaration)
    (h : candidate.evidence ≠ .formal) :
    admitDeclaration current? candidate = .error .candidateNotFormal := by
  simp [admitDeclaration, h]

theorem admit_statement_conflict (current candidate : Declaration)
    (hcurrent : current.evidence = .formal)
    (hkey : current.logicalKey = candidate.logicalKey)
    (hstatement : current.statementHash ≠ candidate.statementHash) :
    admitDeclaration (some current) { candidate with evidence := .formal } =
      .error .statementConflict := by
  simp [admitDeclaration, hcurrent, hkey, hstatement]

theorem admit_same_statement_preserves_origin (current candidate : Declaration)
    (hcurrent : current.evidence = .formal)
    (hcandidate : candidate.evidence = .formal)
    (hkey : current.logicalKey = candidate.logicalKey)
    (hstatement : current.statementHash = candidate.statementHash) :
    admitDeclaration (some current) candidate = .ok current := by
  simp [admitDeclaration, hcurrent, hcandidate, hkey, hstatement]

end Qf
