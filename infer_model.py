import argparse
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

from column_mapping import map_output_columns


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run ML inference on network flows")
    p.add_argument("--input",    default="output.csv")
    p.add_argument("--model",    default="artifacts/model.pkl")
    p.add_argument("--scaler",   default="artifacts/scaler.pkl")
    p.add_argument("--features", default="artifacts/feature_order.json")
    p.add_argument("--output",   default="prediction.csv")
    return p


def _load_artifacts(model_path, scaler_path, features_path):
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    with open(scaler_path, "rb") as f:
        scaler = pickle.load(f)
    with open(features_path, "r", encoding="utf-8") as f:
        features = json.load(f)
    return model, scaler, features


def _prepare(df: pd.DataFrame, feature_order: list[str]) -> np.ndarray:
    mapped = map_output_columns(df)
    aligned = mapped.reindex(columns=feature_order, fill_value=0)
    aligned = aligned.apply(pd.to_numeric, errors="coerce")
    aligned = aligned.replace([np.inf, -np.inf], np.nan).fillna(0)
    return aligned


def infer_new_rows(
    input_path: Path,
    output_path: Path,
    model_path: Path,
    scaler_path: Path,
    features_path: Path,
    processed_rows: int,
) -> int:
    raw = pd.read_csv(input_path)
    new_rows = raw.iloc[processed_rows:]

    if new_rows.empty:
        return processed_rows

    model, scaler, features = _load_artifacts(model_path, scaler_path, features_path)
    X = _prepare(new_rows, features)
    X_scaled = scaler.transform(X)
    predictions = model.predict(X_scaled)

    out = new_rows.copy()
    out["ml_prediction"] = predictions

    write_header = not output_path.exists() or output_path.stat().st_size == 0
    out.to_csv(output_path, mode="a", index=False, header=write_header)

    n_attacks = (pd.Series(predictions).str.upper() != "BENIGN").sum()
    print(f"[ML] {len(new_rows)} new flows → {n_attacks} flagged as attack")
    return processed_rows + len(new_rows)


def main() -> None:
    args = build_parser().parse_args()
    raw = pd.read_csv(args.input)
    model, scaler, features = _load_artifacts(
        args.model, args.scaler, args.features
    )
    X = _prepare(raw, features)
    X_scaled = scaler.transform(X)
    predictions = model.predict(X_scaled)

    out = map_output_columns(raw).copy()
    out["ml_prediction"] = predictions
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.output, index=False)

    attacks = (pd.Series(predictions).str.upper() != "BENIGN").sum()
    print(f"Rows: {len(raw)} | Attacks detected: {attacks} | Saved: {args.output}")


if __name__ == "__main__":
    main()
