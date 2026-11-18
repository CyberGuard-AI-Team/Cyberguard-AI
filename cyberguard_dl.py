"""Local Autoencoder model for CyberGuard log anomaly analysis.

The model is intentionally compact so it can train on CPU inside Streamlit.
It learns only from the events in the current workspace. Its reconstruction
score is a relative review priority, not proof that a device is compromised.
"""

from __future__ import annotations

import math
import random
from dataclasses import asdict, dataclass
from typing import Callable, Iterable

import numpy as np
import pandas as pd


ProgressCallback = Callable[[str, float], None]


class DeepLearningUnavailable(RuntimeError):
    """Raised when the optional PyTorch runtime cannot be imported."""


@dataclass
class ModelDiagnostic:
    model: str
    family: str
    status: str
    final_loss: float | None
    records: int
    note: str


def _load_torch():
    try:
        import torch
        from torch import nn
    except ImportError as exc:  # pragma: no cover - depends on deployment
        raise DeepLearningUnavailable(
            "The PyTorch runtime is unavailable. Isolation Forest can still run, "
            "but the Autoencoder requires the project dependencies to be installed."
        ) from exc
    return torch, nn


def _seed_everything(torch, seed: int = 42) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if hasattr(torch, "set_num_threads"):
        torch.set_num_threads(max(1, min(2, torch.get_num_threads())))


def _normalise_scores(values: Iterable[float]) -> np.ndarray:
    scores = np.asarray(list(values), dtype=np.float64)
    scores = np.nan_to_num(scores, nan=0.0, posinf=0.0, neginf=0.0)
    if scores.size == 0:
        return scores
    low, high = float(scores.min()), float(scores.max())
    if math.isclose(low, high):
        return np.zeros_like(scores)
    return (scores - low) / (high - low) * 100.0


def _prepare_structured_features(events: list[dict]) -> tuple[pd.DataFrame, np.ndarray]:
    frame = pd.DataFrame(events).copy()
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame["timestamp"] = frame["timestamp"].fillna(pd.Timestamp.now(tz="UTC"))
    frame = frame.sort_values("timestamp").reset_index(drop=True)
    for column in ("eventType", "user", "sourceIp", "status", "severity"):
        if column not in frame:
            frame[column] = "unknown"
        frame[column] = frame[column].fillna("unknown").astype(str)

    hour = frame["timestamp"].dt.hour + frame["timestamp"].dt.minute / 60.0
    severity = frame["severity"].map(
        {"Informational": 0.0, "Low": 1.0, "Medium": 2.0, "High": 3.0, "Critical": 4.0}
    ).fillna(0.0)
    type_frequency = frame.groupby("eventType")["eventType"].transform("size")
    actor_frequency = frame.groupby("user")["user"].transform("size")
    source_frequency = frame.groupby("sourceIp")["sourceIp"].transform("size")

    numeric = pd.DataFrame(
        {
            "hour_sin": np.sin(2 * np.pi * hour / 24.0),
            "hour_cos": np.cos(2 * np.pi * hour / 24.0),
            "severity": severity / 4.0,
            "type_frequency": np.log1p(type_frequency) / max(np.log1p(len(frame)), 1.0),
            "actor_frequency": np.log1p(actor_frequency) / max(np.log1p(len(frame)), 1.0),
            "source_frequency": np.log1p(source_frequency) / max(np.log1p(len(frame)), 1.0),
        }
    )
    encoded = pd.get_dummies(
        frame[["eventType", "status", "severity"]],
        prefix=["type", "status", "severity"],
        dtype=float,
    )
    matrix = pd.concat([numeric, encoded], axis=1).astype(np.float32).to_numpy()
    means = matrix.mean(axis=0, keepdims=True)
    standard_deviation = matrix.std(axis=0, keepdims=True)
    matrix = (matrix - means) / np.where(standard_deviation < 1e-6, 1.0, standard_deviation)
    return frame, matrix.astype(np.float32)


def _autoencoder_scores(torch, nn, matrix: np.ndarray, epochs: int) -> tuple[np.ndarray, float]:
    input_size = matrix.shape[1]
    hidden_size = max(8, min(48, input_size // 2 if input_size > 12 else 12))
    bottleneck = max(4, min(16, hidden_size // 2))

    class StructuredAutoencoder(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.network = nn.Sequential(
                nn.Linear(input_size, hidden_size),
                nn.ReLU(),
                nn.Linear(hidden_size, bottleneck),
                nn.ReLU(),
                nn.Linear(bottleneck, hidden_size),
                nn.ReLU(),
                nn.Linear(hidden_size, input_size),
            )

        def forward(self, values):
            return self.network(values)

    values = torch.tensor(matrix, dtype=torch.float32)
    model = StructuredAutoencoder()
    optimiser = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=1e-5)
    loss_function = nn.MSELoss()
    final_loss = 0.0
    model.train()
    for _ in range(epochs):
        optimiser.zero_grad()
        reconstruction = model(values)
        loss = loss_function(reconstruction, values)
        loss.backward()
        optimiser.step()
        final_loss = float(loss.detach().cpu())

    model.eval()
    with torch.no_grad():
        errors = ((model(values) - values) ** 2).mean(dim=1).cpu().numpy()
    return errors, final_loss


def deep_learning_scores(
    events: list[dict], progress: ProgressCallback | None = None
) -> tuple[pd.DataFrame, list[dict]]:
    """Train one compact Autoencoder and return one relative score per event."""
    if len(events) < 8:
        raise ValueError("At least 8 events are required for Autoencoder analysis.")

    torch, nn = _load_torch()
    _seed_everything(torch)
    frame, matrix = _prepare_structured_features(events)
    records = len(frame)
    epochs = 28 if records < 150 else 18
    note = (
        "Exploratory baseline: fewer than 30 records were available."
        if records < 30
        else "Trained on the current workspace records."
    )

    if progress:
        progress("Autoencoder", 0.25)
    raw_scores, final_loss = _autoencoder_scores(torch, nn, matrix, epochs)
    results = pd.DataFrame(
        {
            "id": frame["id"].astype(str),
            "autoencoder_score": _normalise_scores(raw_scores),
        }
    )
    diagnostics = [
        ModelDiagnostic(
            "Autoencoder",
            "Reconstruction neural network",
            "Completed",
            final_loss,
            records,
            note,
        )
    ]
    if progress:
        progress("Complete", 1.0)
    return results, [asdict(item) for item in diagnostics]
