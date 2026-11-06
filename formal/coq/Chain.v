Require Import Coq.Lists.List.
Import ListNotations.

Section ChainHeight.
  Variable Block : Type.
  Definition height (blocks : list Block) : nat := length blocks.

  Theorem height_zero_iff_empty :
    forall blocks, height blocks = 0 <-> blocks = [].
  Proof.
    intros blocks. split.
    - intros H. destruct blocks as [|block rest].
      + reflexivity.
      + simpl in H. discriminate H.
    - intros H. rewrite H. reflexivity.
  Qed.
End ChainHeight.
