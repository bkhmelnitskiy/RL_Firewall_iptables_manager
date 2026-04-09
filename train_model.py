import argparse
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


DATASET_DEFAULT = (
    "datasets/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Train Random Forest on CICIDS2017")
    p.add_argument("--dataset", default=DATASET_DEFAULT)
    p.add_argument("--model-out",    default="artifacts/model.pkl")
    p.add_argument("--scaler-out",   default="artifacts/scaler.pkl")
    p.add_argument("--features-out", default="artifacts/feature_order.json")
    p.add_argument("--n-estimators", type=int, default=100)
    p.add_argument("--test-size",    type=float, default=0.2)
    return p


def load_dataset(path: str) -> tuple[pd.DataFrame, pd.Series]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Dataset not found: {file_path}")

    df = pd.read_csv(file_path)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise ValueError("'Label' column missing from dataset.")

    y = df["Label"].str.strip()
    X = df.drop(columns=["Label"])

    # Keep only numeric columns; replace inf/NaN with 0.
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    return X, y


def train(args) -> None:
    print(f"Loading dataset: {args.dataset}")
    X, y = load_dataset(args.dataset)

    print(f"Samples: {len(X)}")
    print("Class distribution:")
    for label, count in y.value_counts().items():
        print(f"  {label:<40} {count:>6}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=args.test_size,
        random_state=42,
        stratify=y,
    )

    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    print(f"\nTraining RandomForest ({args.n_estimators} trees, class_weight=balanced) …")
    model = RandomForestClassifier(
        n_estimators=args.n_estimators,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_sc, y_train)

    y_pred = model.predict(X_test_sc)
    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred, digits=4))

    # Save artifacts
    for path_str in (args.model_out, args.scaler_out, args.features_out):
        Path(path_str).parent.mkdir(parents=True, exist_ok=True)

    with open(args.model_out, "wb") as f:
        pickle.dump(model, f)
    with open(args.scaler_out, "wb") as f:
        pickle.dump(scaler, f)
    with open(args.features_out, "w", encoding="utf-8") as f:
        json.dump(X.columns.tolist(), f, indent=2)

    print(f"Saved model   → {args.model_out}")
    print(f"Saved scaler  → {args.scaler_out}")
    print(f"Saved features → {args.features_out}")


if __name__ == "__main__":
    train(build_parser().parse_args())
