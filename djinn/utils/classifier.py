from dataclasses import dataclass, field

import torch
from torch import Tensor
from torch.nn.functional import (
    binary_cross_entropy_with_logits as bce_with_logits,
)
from torch.nn.functional import (
    cross_entropy,
)
from torch.nn.functional import sigmoid


@dataclass
class InlpResult:
    """Result of Iterative Nullspace Projection (NLP)."""

    losses: list[float] = field(default_factory=list)
    classifiers: list["Classifier"] = field(default_factory=list)


@dataclass
class RegularizationPath:
    """Result of cross-validation."""

    penalties: list[float]
    losses: list[float]

    @property
    def best_penalty(self) -> float:
        """Returns the best L2 regularization penalty."""
        return self.penalties[self.losses.index(self.best_loss)]

    @property
    def best_loss(self) -> float:
        """Returns the best loss."""
        return min(self.losses)


class Classifier(torch.nn.Module):
    """Linear classifier trained with supervised learning."""

    def __init__(
        self,
        input_dim: int,
        num_classes: int = 2,
        device: str | torch.device | None = None,
        dtype: torch.dtype | None = None,
    ):
        super().__init__()

        self.linear = torch.nn.Linear(
            input_dim, num_classes if num_classes > 2 else 1, device=device, dtype=dtype
        )
        self.linear.bias.data.zero_()
        self.linear.weight.data.zero_()

    def forward(self, x: Tensor) -> Tensor:
        return self.linear(x).squeeze(-1)

    @torch.enable_grad()
    def fit(
        self,
        x: Tensor,
        y: Tensor,
        *,
        l2_penalty: float = 0.001,
        max_iter: int = 10_000,
    ) -> float:
        """Fits the model to the input data using L-BFGS with L2 regularization.

        Args:
            x: Input tensor of shape (N, D), where N is the number of samples and D is
                the input dimension.
            y: Target tensor of shape (N,) for binary classification or (N, C) for
                multiclass classification, where C is the number of classes.
            l2_penalty: L2 regularization strength.
            max_iter: Maximum number of iterations for the L-BFGS optimizer.

        Returns:
            Final value of the loss function after optimization.
        """
        optimizer = torch.optim.LBFGS(
            self.parameters(),
            line_search_fn="strong_wolfe",
            max_iter=max_iter,
        )

        self.linear.bias.data.zero_()
        self.linear.weight.data.zero_()

        num_classes = self.linear.out_features
        loss_fn = bce_with_logits if num_classes == 1 else cross_entropy
        loss = torch.inf
        y = y.to(
            torch.get_default_dtype() if num_classes == 1 else torch.long,
        )

        def closure():
            nonlocal loss
            optimizer.zero_grad()

            # Calculate the loss function
            logits = self(x).squeeze(-1)
            loss = loss_fn(logits, y)
            if l2_penalty:
                reg_loss = loss + l2_penalty * self.linear.weight.square().sum()
            else:
                reg_loss = loss

            reg_loss.backward()
            return float(reg_loss)

        optimizer.step(closure)
        return float(loss)

    @torch.no_grad()
    def evaluate(
        self,
        x: Tensor,
        y: Tensor,
        sequence_ids: Tensor | None = None,
    ) -> dict[str, float]:
        """Evaluate the classifier on test data.

        Args:
            x: Input tensor of shape (N, D)
            y: Target tensor of shape (N,)
            sequence_ids: Optional tensor of shape (N,) indicating which sequence
                each token belongs to. If provided, will compute sequence-averaged BCE.

        Returns:
            Dictionary containing:
                - 'bce': Binary cross-entropy loss (per-token average)
                - 'accuracy': Classification accuracy
                - 'sequence_bce': BCE averaged over sequences (if sequence_ids provided)
        """
        num_classes = self.linear.out_features
        loss_fn = bce_with_logits if num_classes == 1 else cross_entropy

        y = y.to(
            torch.get_default_dtype() if num_classes == 1 else torch.long,
        )

        logits = self(x).squeeze(-1)
        bce = float(loss_fn(logits, y))

        # Compute accuracy
        if num_classes == 1:
            preds = (logits > 0).long()
        else:
            preds = logits.argmax(dim=-1)
        accuracy = float((preds == y).float().mean())

        metrics = {
            'bce': bce,
            'accuracy': accuracy,
        }

        # Compute sequence-averaged BCE if sequence_ids provided
        if sequence_ids is not None:
            sequence_bces = []
            unique_seqs = torch.unique(sequence_ids)

            for seq_id in unique_seqs:
                mask = sequence_ids == seq_id
                seq_logits = logits[mask]
                seq_y = y[mask]

                # Average logits over the sequence, then compute BCE
                avg_logit = seq_logits.mean()
                seq_label = seq_y[0].float()  # All labels in a sequence are the same

                # BCE for this sequence's averaged prediction
                seq_bce = float(bce_with_logits(avg_logit.unsqueeze(0), seq_label.unsqueeze(0)))
                sequence_bces.append(seq_bce)

            metrics['sequence_bce'] = float(torch.tensor(sequence_bces).mean())

        return metrics

    @torch.no_grad()
    def fit_cv(
        self,
        x: Tensor,
        y: Tensor,
        *,
        k: int = 5,
        max_iter: int = 10_000,
        num_penalties: int = 10,
        seed: int = 42,
    ) -> RegularizationPath:
        """Fit using k-fold cross-validation to select the best L2 penalty.

        Args:
            x: Input tensor of shape (N, D), where N is the number of samples and D is
                the input dimension.
            y: Target tensor of shape (N,) for binary classification or (N, C) for
                multiclass classification, where C is the number of classes.
            k: Number of folds for k-fold cross-validation.
            max_iter: Maximum number of iterations for the L-BFGS optimizer.
            num_penalties: Number of L2 regularization penalties to try.
            seed: Random seed for the k-fold cross-validation.

        Returns:
            `RegularizationPath` containing the penalties tried and the validation loss
            achieved using that penalty, averaged across the folds.
        """
        num_samples = x.shape[0]
        if k < 3:
            raise ValueError("`k` must be at least 3")
        if k > num_samples:
            raise ValueError("`k` must be less than or equal to the number of samples")

        rng = torch.Generator(device=x.device)
        rng.manual_seed(seed)

        fold_size = num_samples // k
        indices = torch.randperm(num_samples, device=x.device, generator=rng)

        # Try a range of L2 penalties, including 0
        l2_penalties = [0.0] + torch.logspace(-4, 4, num_penalties).tolist()

        num_classes = self.linear.out_features
        loss_fn = bce_with_logits if num_classes == 1 else cross_entropy
        losses = x.new_zeros((k, num_penalties + 1))
        y = y.to(
            torch.get_default_dtype() if num_classes == 1 else torch.long,
        )

        for i in range(k):
            start, end = i * fold_size, (i + 1) * fold_size
            train_indices = torch.cat([indices[:start], indices[end:]])
            val_indices = indices[start:end]

            train_x, train_y = x[train_indices], y[train_indices]
            val_x, val_y = x[val_indices], y[val_indices]

            # Regularization path with warm-starting
            for j, l2_penalty in enumerate(l2_penalties):
                self.fit(train_x, train_y, l2_penalty=l2_penalty, max_iter=max_iter)

                logits = self(val_x).squeeze(-1)
                loss = loss_fn(logits, val_y)
                losses[i, j] = loss


        mean_losses = losses.mean(dim=0)
        best_idx = mean_losses.argmin()

        # Refit with the best penalty
        best_penalty = l2_penalties[best_idx]
        self.fit(x, y, l2_penalty=best_penalty, max_iter=max_iter)
        return RegularizationPath(l2_penalties, mean_losses.tolist())
