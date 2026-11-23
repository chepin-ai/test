/-!
# Conservative relation composition for the QF knowledge lineage.

Only relations with a stated composition rule are closed. Coupling, symmetry,
duality and bridging deliberately have no generic composition rule. In
particular, an implementation must not turn a path of couplings or bridges into
an equivalence by taking transitive closure.
-/

namespace Qf

inductive Relation where
  | coupling | embedding | equivalence | symmetry | duality | implication | dependency | bridging
  deriving DecidableEq, Repr

/-- The four relations admitted to conservative transitive closure. -/
def Relation.hasGenericTransitiveClosure : Relation → Bool
  | .embedding | .equivalence | .implication | .dependency => true
  | _ => false

/-- A deliberately partial composition operation: absence of a rule fails closed. -/
def Relation.compose : Relation → Relation → Option Relation
  | .equivalence, .equivalence => some .equivalence
  | .embedding, .embedding => some .embedding
  | .equivalence, .embedding => some .embedding
  | .embedding, .equivalence => some .embedding
  | .implication, .implication => some .implication
  | .dependency, .dependency => some .dependency
  | _, _ => none

theorem coupling_not_transitive : Relation.compose .coupling .coupling = none := rfl

theorem bridging_not_transitive : Relation.compose .bridging .bridging = none := rfl

theorem symmetry_not_generically_transitive : Relation.compose .symmetry .symmetry = none := rfl

theorem duality_not_generically_transitive : Relation.compose .duality .duality = none := rfl

theorem embedding_closed : Relation.compose .embedding .embedding = some .embedding := rfl

theorem implication_closed : Relation.compose .implication .implication = some .implication := rfl

theorem dependency_closed : Relation.compose .dependency .dependency = some .dependency := rfl

theorem equivalence_embedding_is_embedding :
    Relation.compose .equivalence .embedding = some .embedding := rfl

end Qf
