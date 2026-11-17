"""Small, local deep-learning models for CyberGuard log anomaly analysis.

The models are intentionally compact so they can train on CPU inside Streamlit.
They learn only from the events in the current workspace. Their scores are
relative review priorities, not probabilities that a device is compromised.
"""

from __future__ import annotations

import math
import random
import re
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
        from torch.nn import functional as functional
    except ImportError as exc:  # pragma: no cover - exercised only on broken deployments
        raise DeepLearningUnavailable(
            "The PyTorch runtime is unavailable. Isolation Forest can still run, "
            "but the deep-learning models require the project dependencies to be installed."
        ) from exc
    return torch, nn, functional


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
    for column in ("eventType", "user", "sourceIp", "status", "severity", "description"):
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
    elapsed = (frame["timestamp"] - frame["timestamp"].min()).dt.total_seconds().fillna(0.0)
    duration = max(float(elapsed.max()), 1.0)

    numeric = pd.DataFrame(
        {
            "hour_sin": np.sin(2 * np.pi * hour / 24.0),
            "hour_cos": np.cos(2 * np.pi * hour / 24.0),
            "severity": severity / 4.0,
            "type_frequency": np.log1p(type_frequency) / max(np.log1p(len(frame)), 1.0),
            "actor_frequency": np.log1p(actor_frequency) / max(np.log1p(len(frame)), 1.0),
            "source_frequency": np.log1p(source_frequency) / max(np.log1p(len(frame)), 1.0),
            "relative_time": elapsed / duration,
        }
    )
    encoded = pd.get_dummies(
        frame[["eventType", "status", "severity"]], prefix=["type", "status", "severity"], dtype=float
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


def _sequence_windows(matrix: np.ndarray) -> tuple[np.ndarray, np.ndarray, int]:
    window = min(6, max(2, len(matrix) // 6))
    windows = np.stack([matrix[index - window : index] for index in range(window, len(matrix))])
    targets = matrix[window:]
    return windows.astype(np.float32), targets.astype(np.float32), window


def _lstm_scores(torch, nn, matrix: np.ndarray, epochs: int) -> tuple[np.ndarray, float]:
    windows, targets, window = _sequence_windows(matrix)
    input_size = matrix.shape[1]
    hidden_size = max(12, min(48, input_size))

    class LogLSTM(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
            self.output = nn.Linear(hidden_size, input_size)

        def forward(self, values):
            encoded, _ = self.lstm(values)
            return self.output(encoded[:, -1, :])

    x_values = torch.tensor(windows, dtype=torch.float32)
    y_values = torch.tensor(targets, dtype=torch.float32)
    model = LogLSTM()
    optimiser = torch.optim.Adam(model.parameters(), lr=0.008, weight_decay=1e-5)
    loss_function = nn.MSELoss()
    final_loss = 0.0
    model.train()
    for _ in range(epochs):
        optimiser.zero_grad()
        prediction = model(x_values)
        loss = loss_function(prediction, y_values)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimiser.step()
        final_loss = float(loss.detach().cpu())
    model.eval()
    with torch.no_grad():
        errors = ((model(x_values) - y_values) ** 2).mean(dim=1).cpu().numpy()
    prefix = np.full(window, float(np.median(errors)) if errors.size else 0.0)
    return np.concatenate([prefix, errors]), final_loss


def _transformer_scores(torch, nn, matrix: np.ndarray, epochs: int) -> tuple[np.ndarray, float]:
    windows, targets, window = _sequence_windows(matrix)
    input_size = matrix.shape[1]
    model_size = 32

    class LogTransformer(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.input_projection = nn.Linear(input_size, model_size)
            self.position = nn.Parameter(torch.zeros(1, window, model_size))
            layer = nn.TransformerEncoderLayer(
                d_model=model_size, nhead=4, dim_feedforward=64, dropout=0.05, batch_first=True
            )
            self.encoder = nn.TransformerEncoder(layer, num_layers=1)
            self.output = nn.Linear(model_size, input_size)

        def forward(self, values):
            hidden = self.input_projection(values) + self.position[:, : values.shape[1], :]
            encoded = self.encoder(hidden)
            return self.output(encoded[:, -1, :])

    x_values = torch.tensor(windows, dtype=torch.float32)
    y_values = torch.tensor(targets, dtype=torch.float32)
    model = LogTransformer()
    optimiser = torch.optim.AdamW(model.parameters(), lr=0.006, weight_decay=1e-4)
    loss_function = nn.MSELoss()
    final_loss = 0.0
    model.train()
    for _ in range(epochs):
        optimiser.zero_grad()
        prediction = model(x_values)
        loss = loss_function(prediction, y_values)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimiser.step()
        final_loss = float(loss.detach().cpu())
    model.eval()
    with torch.no_grad():
        errors = ((model(x_values) - y_values) ** 2).mean(dim=1).cpu().numpy()
    prefix = np.full(window, float(np.median(errors)) if errors.size else 0.0)
    return np.concatenate([prefix, errors]), final_loss


def _normalise_token(token: str) -> str:
    token = token.lower()
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", token):
        return "<ip>"
    if re.fullmatch(r"0x[0-9a-f]+", token):
        return "<hex>"
    if any(character.isdigit() for character in token):
        return re.sub(r"\d+", "<num>", token)
    return token


def _tokenise(text: str) -> list[str]:
    return [_normalise_token(token) for token in re.findall(r"[A-Za-z0-9_.:\\/-]+", text) if token]


def _bert_scores(torch, nn, functional, frame: pd.DataFrame, epochs: int) -> tuple[np.ndarray, float, int]:
    special_tokens = ["[PAD]", "[UNK]", "[MASK]", "[CLS]"]
    documents = [
        _tokenise(f"{row.eventType} {row.severity} {row.status} {row.description}")
        for row in frame.itertuples(index=False)
    ]
    counts: dict[str, int] = {}
    for document in documents:
        for token in document:
            counts[token] = counts.get(token, 0) + 1
    vocabulary_tokens = sorted(counts, key=lambda token: (-counts[token], token))[:508]
    vocabulary = {token: index for index, token in enumerate(special_tokens + vocabulary_tokens)}
    maximum_length = min(32, max(6, max((len(document) for document in documents), default=5) + 1))
    token_rows: list[list[int]] = []
    for document in documents:
        ids = [vocabulary["[CLS]"]] + [vocabulary.get(token, vocabulary["[UNK]"]) for token in document]
        ids = ids[:maximum_length]
        ids += [vocabulary["[PAD]"]] * (maximum_length - len(ids))
        token_rows.append(ids)
    input_ids = torch.tensor(token_rows, dtype=torch.long)
    attention_mask = input_ids.ne(vocabulary["[PAD]"])
    vocabulary_size = len(vocabulary)
    model_size = 32

    class MiniLogBERT(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.token_embeddings = nn.Embedding(vocabulary_size, model_size, padding_idx=vocabulary["[PAD]"])
            self.position_embeddings = nn.Embedding(maximum_length, model_size)
            layer = nn.TransformerEncoderLayer(
                d_model=model_size, nhead=4, dim_feedforward=64, dropout=0.08, batch_first=True
            )
            self.encoder = nn.TransformerEncoder(layer, num_layers=1)
            self.language_head = nn.Linear(model_size, vocabulary_size)

        def forward(self, values, mask):
            positions = torch.arange(values.shape[1], device=values.device).unsqueeze(0)
            hidden = self.token_embeddings(values) + self.position_embeddings(positions)
            encoded = self.encoder(hidden, src_key_padding_mask=~mask)
            return self.language_head(encoded)

    def make_masked_batch(epoch: int):
        masked = input_ids.clone()
        labels = torch.full_like(input_ids, -100)
        for row_index in range(len(input_ids)):
            positions = torch.where(input_ids[row_index].gt(vocabulary["[CLS]"]) & attention_mask[row_index])[0]
            if len(positions) == 0:
                continue
            count = max(1, int(math.ceil(len(positions) * 0.15)))
            chosen = positions[(torch.arange(count) * 7 + row_index + epoch) % len(positions)]
            labels[row_index, chosen] = input_ids[row_index, chosen]
            masked[row_index, chosen] = vocabulary["[MASK]"]
        return masked, labels

    model = MiniLogBERT()
    optimiser = torch.optim.AdamW(model.parameters(), lr=0.004, weight_decay=1e-4)
    final_loss = 0.0
    model.train()
    for epoch in range(epochs):
        masked, labels = make_masked_batch(epoch)
        optimiser.zero_grad()
        logits = model(masked, attention_mask)
        loss = functional.cross_entropy(logits.reshape(-1, vocabulary_size), labels.reshape(-1), ignore_index=-100)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimiser.step()
        final_loss = float(loss.detach().cpu())

    model.eval()
    masked, labels = make_masked_batch(0)
    with torch.no_grad():
        logits = model(masked, attention_mask)
        token_loss = functional.cross_entropy(
            logits.transpose(1, 2), labels, ignore_index=-100, reduction="none"
        )
        valid = labels.ne(-100)
        losses = (token_loss * valid).sum(dim=1) / valid.sum(dim=1).clamp(min=1)
    return losses.cpu().numpy(), final_loss, vocabulary_size


def deep_learning_scores(
    events: list[dict], progress: ProgressCallback | None = None
) -> tuple[pd.DataFrame, list[dict]]:
    """Train four compact DL models and return one relative score per event."""
    if len(events) < 8:
        raise ValueError("At least 8 events are required for deep-learning analysis.")
    torch, nn, functional = _load_torch()
    _seed_everything(torch)
    frame, matrix = _prepare_structured_features(events)
    records = len(frame)
    epochs = 28 if records < 150 else 18
    diagnostics: list[ModelDiagnostic] = []
    results = pd.DataFrame({"id": frame["id"].astype(str)})
    limited_note = (
        "Exploratory baseline: fewer than 30 records were available."
        if records < 30
        else "Trained on the current workspace records."
    )

    model_jobs = [
        ("autoencoder_score", "Autoencoder", "Reconstruction", lambda: _autoencoder_scores(torch, nn, matrix, epochs)),
        ("lstm_score", "LSTM", "Sequence prediction", lambda: _lstm_scores(torch, nn, matrix, epochs)),
        (
            "transformer_score",
            "Transformer",
            "Sequence attention",
            lambda: _transformer_scores(torch, nn, matrix, max(14, epochs - 6)),
        ),
    ]

    for index, (column, model_name, family, job) in enumerate(model_jobs):
        if progress:
            progress(model_name, index / 4.0)
        try:
            raw_scores, final_loss = job()
            results[column] = _normalise_scores(raw_scores)
            diagnostics.append(ModelDiagnostic(model_name, family, "Completed", final_loss, records, limited_note))
        except Exception as exc:  # keep the ensemble usable if one experimental model fails
            results[column] = np.nan
            diagnostics.append(ModelDiagnostic(model_name, family, "Unavailable", None, records, str(exc)))

    if progress:
        progress("BERT-style log model", 0.75)
    try:
        raw_scores, final_loss, vocabulary_size = _bert_scores(
            torch, nn, functional, frame, max(10, epochs // 2)
        )
        results["bert_score"] = _normalise_scores(raw_scores)
        diagnostics.append(
            ModelDiagnostic(
                "BERT-style log model",
                "Masked language modelling",
                "Completed",
                final_loss,
                records,
                f"{limited_note} Vocabulary size: {vocabulary_size}.",
            )
        )
    except Exception as exc:
        results["bert_score"] = np.nan
        diagnostics.append(
            ModelDiagnostic("BERT-style log model", "Masked language modelling", "Unavailable", None, records, str(exc))
        )

    if progress:
        progress("Complete", 1.0)
    return results, [asdict(item) for item in diagnostics]

