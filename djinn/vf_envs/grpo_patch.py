"""
Monkey patch for GRPO trainer importance weights calculation.

This patches the compute_loss method in GRPOTrainer to use the modified
importance weights calculation from your recent paper implementation.
"""

import torch
from typing import Dict


def patch_grpo_importance_weights():
    """
    Apply monkey patch to modify importance weights calculation in GRPOTrainer.
    
    This modifies the coef_1 calculation in the compute_loss method to implement
    your custom importance weights formula from the recent paper.
    """
    try:
        from verifiers.trainers import GRPOTrainer
        from verifiers.trainers.grpo_trainer import nanmin, nanmax
    except ImportError:
        print("Warning: Could not import GRPOTrainer from verifiers.trainers")
        return False
    
    # Store the original compute_loss method
    original_compute_loss = GRPOTrainer.compute_loss
    
    def patched_compute_loss(self, model, inputs: Dict[str, torch.Tensor], return_outputs: bool = False, num_items_in_batch: int | None = None) -> torch.Tensor:
        """
        Patched compute_loss method with modified importance weights calculation.
        """
        mode = "train"
        # Compute the per-token log probabilities for the model
        input_ids, attention_mask = inputs["input_ids"], inputs["attention_mask"]

        # prompt is at least 1 token
        completion_mask = attention_mask[:, 1:]
        logits_to_keep = completion_mask.size(1)
        per_token_logps = self._get_per_token_logps(
            model, input_ids, attention_mask, logits_to_keep
        )
        # Compute the loss
        advantages = inputs["advantages"]
        # When using num_iterations == 1, old_per_token_logps == per_token_logps,
        # so we can skip it's computation (see _generate_and_score_completions) and use per_token_logps.detach() instead.
        old_per_token_logps = (
            per_token_logps.detach()
            if inputs["old_per_token_logps"] is None
            else inputs["old_per_token_logps"]
        )
        
        # MODIFIED LINE: Your custom importance weights calculation
        # Replace the original line with your paper's formula
        coef_1 = torch.exp((per_token_logps * completion_mask - old_per_token_logps * completion_mask).sum(dim=1) / completion_mask.sum(dim=1)).unsqueeze(1)
        
        coef_2 = torch.clamp(coef_1, 1 - self.epsilon_low, 1 + self.epsilon_high)

        if self.delta is not None:
            # Use clamp instead of min to handle tensor-float comparison
            per_token_loss1 = torch.clamp(
                coef_1, max=self.delta
            ) * advantages.unsqueeze(1)
        else:
            # Original GRPO clipping (only lower bound implicitly applied by the final min)
            per_token_loss1 = coef_1 * advantages.unsqueeze(1)

        per_token_loss2 = coef_2 * advantages.unsqueeze(1)
        per_token_loss = -torch.min(per_token_loss1, per_token_loss2)

        # Compute the KL divergence between the model and the reference model
        if self.beta != 0.0:
            with torch.no_grad():
                if self.ref_model is not None:
                    ref_per_token_logps = self._get_per_token_logps(
                        self.ref_model, input_ids, attention_mask, logits_to_keep
                    )
                else:
                    with self.accelerator.unwrap_model(self.model).disable_adapter():  # type: ignore
                        ref_per_token_logps = self._get_per_token_logps(
                            self.model, input_ids, attention_mask, logits_to_keep
                        )
            per_token_kl = (
                torch.exp(ref_per_token_logps - per_token_logps)
                - (ref_per_token_logps - per_token_logps)
                - 1
            )
            per_token_loss = per_token_loss + self.beta * per_token_kl
            mean_kl = (per_token_kl * completion_mask).sum() / completion_mask.sum()
            self._metrics[mode]["kl"].append(
                self.accelerator.gather_for_metrics(mean_kl).nanmean().item()
            )  # type: ignore
        if self.loss_type == "grpo":
            loss = (
                (per_token_loss * completion_mask).sum(-1)
                / completion_mask.sum(-1).clamp(min=1.0)
            ).mean()
        elif self.loss_type == "bnpo":
            loss = (
                per_token_loss * completion_mask
            ).sum() / completion_mask.sum().clamp(min=1.0)
        elif self.loss_type == "dr_grpo":
            loss = (per_token_loss * completion_mask).sum() / (
                per_token_loss.size(0) * self.max_seq_len
            )  # type: ignore
        else:
            raise ValueError(f"Unknown loss type: {self.loss_type}")

        # Compute the clipped probability ratios
        is_low_clipped = (coef_1 < 1 - self.epsilon_low) & (advantages.unsqueeze(1) < 0)
        is_high_clipped = (coef_1 > 1 + self.epsilon_high) & (
            advantages.unsqueeze(1) > 0
        )
        is_region_clipped = is_low_clipped | is_high_clipped

        low_clip = (is_low_clipped * completion_mask).sum() / completion_mask.sum()
        high_clip = (is_high_clipped * completion_mask).sum() / completion_mask.sum()
        clip_ratio = (is_region_clipped * completion_mask).sum() / completion_mask.sum()

        gathered_low_clip = self.accelerator.gather_for_metrics(low_clip)
        self._metrics[mode]["clip_ratio/low_mean"].append(
            gathered_low_clip.nanmean().item()
        )  # type: ignore
        self._metrics[mode]["clip_ratio/low_min"].append(
            nanmin(gathered_low_clip).item()
        )  # type: ignore
        gathered_high_clip = self.accelerator.gather_for_metrics(high_clip)
        self._metrics[mode]["clip_ratio/high_mean"].append(
            gathered_high_clip.nanmean().item()
        )  # type: ignore
        self._metrics[mode]["clip_ratio/high_max"].append(
            nanmax(gathered_high_clip).item()
        )  # type: ignore
        gathered_clip_ratio = self.accelerator.gather_for_metrics(clip_ratio)
        self._metrics[mode]["clip_ratio/region_mean"].append(
            gathered_clip_ratio.nanmean().item()
        )  # type: ignore
        return loss
    
    # Apply the patch
    GRPOTrainer.compute_loss = patched_compute_loss
    
    print("✅ Applied GRPO importance weights patch")
    return True

# Example usage functions
def apply_djinn_grpo_patch():
    """Apply the specific patch for djinn training"""
    return patch_grpo_importance_weights()


if __name__ == "__main__":
    # Test the patch
    success = apply_djinn_grpo_patch()
    if success:
        print("Patch applied successfully!")
    else:
        print("Failed to apply patch")