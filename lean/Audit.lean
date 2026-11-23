import Qf

#check Qf.coupling_not_transitive
#check Qf.bridging_not_transitive
#check Qf.lossy_projection_not_formal
#check Qf.admit_informal_rejected
#check Qf.admit_statement_conflict
#check Qf.admit_same_statement_preserves_origin

#print axioms Qf.coupling_not_transitive
#print axioms Qf.bridging_not_transitive
#print axioms Qf.lossy_projection_not_formal
#print axioms Qf.admit_informal_rejected
#print axioms Qf.admit_statement_conflict
#print axioms Qf.admit_same_statement_preserves_origin

namespace Qf.Audit

private def current : Qf.Declaration where
  logicalKey := "qf.demo"
  statementHash := "statement-a"
  profileHash := "profile-a"
  sourceCommit := "commit-a"
  evidence := .formal

private def conflicting : Qf.Declaration where
  logicalKey := "qf.demo"
  statementHash := "statement-b"
  profileHash := "profile-b"
  sourceCommit := "commit-b"
  evidence := .formal

-- Expected: Except.error Qf.SyncError.statementConflict
#eval Qf.admitDeclaration (some current) conflicting

-- Expected: Except.ok current, even though the attestation environment differs.
#eval Qf.admitDeclaration (some current) { conflicting with statementHash := "statement-a" }

-- Expected: projectEvidence lossy formal = Evidence.candidate
#eval Qf.projectEvidence .lossy .formal

end Qf.Audit
