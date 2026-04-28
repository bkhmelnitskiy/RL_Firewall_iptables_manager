import argparse
import json
import pickle
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


DATASET_DEFAULT = "datasets/"

# Columns that leak identity or are redundant with other features
DEFAULT_EXCLUDE = [
    "Destination Port",
    "Source Port",
    "Subflow Fwd Bytes",
    "Subflow Bwd Bytes",
    "Subflow Fwd Packets",
    "Subflow Bwd Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Total Fwd Packets",
    "Total Backward Packets",
]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Train Random Forest on CICIDS2017")
    p.add_argument(
        "--dataset", default=DATASET_DEFAULT,
        help="Path to a single CSV file or a folder with CSV files",
    )
    p.add_argument("--model-out",     default="artifacts/model.pkl")
    p.add_argument("--scaler-out",    default="artifacts/scaler.pkl")
    p.add_argument("--features-out",  default="artifacts/feature_order.json")
    p.add_argument("--plots-out",     default="artifacts/plots")
    p.add_argument("--n-estimators",  type=int,   default=100)
    p.add_argument("--test-size",     type=float, default=0.2)
    p.add_argument(
        "--sample-frac", type=float, default=None,
        help="Fraction of rows to sample from each file (e.g. 0.3 = 30%%). "
             "Reduces RAM usage. Default: use all rows.",
    )
    p.add_argument(
        "--exclude-features", type=str, default=None,
        help="Comma-separated list of extra columns to drop (added on top of defaults). "
             "Use --no-default-exclude to disable the built-in exclusion list.",
    )
    p.add_argument(
        "--no-default-exclude", action="store_true",
        help="Disable the built-in DEFAULT_EXCLUDE list.",
    )
    p.add_argument(
        "--benign-frac", type=float, default=0.1,
        help="Fraction of BENIGN rows to keep (default: 0.1 = 10%%). "
             "Reduces dominance of normal traffic. Use 1.0 to keep all.",
    )
    return p


def load_csv(path: Path, sample_frac: float | None) -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise ValueError(f"'Label' column missing in {path}")

    if sample_frac is not None:
        df = df.groupby("Label", group_keys=False).apply(
            lambda g: g.sample(frac=sample_frac, random_state=42)
        )

    y = df["Label"].str.strip()
    X = df.drop(columns=["Label"])
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    return X, y


def build_exclude_list(args) -> list[str]:
    excluded = [] if args.no_default_exclude else list(DEFAULT_EXCLUDE)
    if args.exclude_features:
        extra = [c.strip() for c in args.exclude_features.split(",") if c.strip()]
        excluded.extend(extra)
    return list(dict.fromkeys(excluded))  # deduplicate, preserve order


def load_dataset(
    path: str, sample_frac: float | None
) -> tuple[pd.DataFrame, pd.Series]:
    p = Path(path)

    if p.is_file():
        csv_files = [p]
    elif p.is_dir():
        csv_files = sorted(p.glob("*.csv"))
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in {p}")
    else:
        raise FileNotFoundError(f"Path not found: {p}")

    frames_X, frames_y = [], []
    for f in csv_files:
        print(f"  loading {f.name} …", end=" ", flush=True)
        X, y = load_csv(f, sample_frac)
        print(f"{len(X):,} rows")
        frames_X.append(X)
        frames_y.append(y)

    X_all = pd.concat(frames_X, ignore_index=True)
    y_all = pd.concat(frames_y, ignore_index=True)
    X_all = X_all.dropna(axis=1)
    return X_all, y_all


def undersample_benign(
    X: pd.DataFrame, y: pd.Series, benign_frac: float
) -> tuple[pd.DataFrame, pd.Series]:
    if benign_frac >= 1.0:
        return X, y
    benign_mask = y == "BENIGN"
    benign_idx = y[benign_mask].sample(frac=benign_frac, random_state=42).index
    keep_idx = y[~benign_mask].index.union(benign_idx)
    X_out = X.loc[keep_idx].reset_index(drop=True)
    y_out = y.loc[keep_idx].reset_index(drop=True)
    before = benign_mask.sum()
    after = len(benign_idx)
    print(f"BENIGN undersampled: {before:,} → {after:,} ({benign_frac*100:.0f}%)")
    return X_out, y_out


def drop_excluded(X: pd.DataFrame, exclude: list[str]) -> pd.DataFrame:
    present = [c for c in exclude if c in X.columns]
    missing = [c for c in exclude if c not in X.columns]
    if present:
        print(f"Excluding {len(present)} columns: {', '.join(present)}")
    if missing:
        print(f"  (not found, skipped: {', '.join(missing)})")
    return X.drop(columns=present)


def save_plots(model, X_test_sc, y_test, y_pred, feature_names, plots_dir: Path) -> None:
    plots_dir.mkdir(parents=True, exist_ok=True)
    classes = model.classes_

    # 1. Confusion matrix
    fig, ax = plt.subplots(figsize=(max(8, len(classes)), max(6, len(classes) - 1)))
    cm = confusion_matrix(y_test, y_pred, labels=classes)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=classes)
    disp.plot(ax=ax, xticks_rotation=45, colorbar=True, cmap="Blues")
    ax.set_title("Confusion Matrix")
    fig.tight_layout()
    fig.savefig(plots_dir / "confusion_matrix.png", dpi=150)
    plt.close(fig)
    print(f"  confusion_matrix.png")

    # 2. Top-20 feature importances
    importances = model.feature_importances_
    top_n = min(20, len(feature_names))
    indices = np.argsort(importances)[::-1][:top_n]
    indices_asc = indices[::-1]  # ascending for barh (best at top)
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(
        [feature_names[i] for i in indices_asc],
        importances[indices_asc],
        color="steelblue",
    )
    ax.set_xlabel("Importance")
    ax.set_title(f"Top {top_n} Feature Importances")
    fig.tight_layout()
    fig.savefig(plots_dir / "feature_importances.png", dpi=150)
    plt.close(fig)
    print(f"  feature_importances.png")

    # 3. Class distribution in test set (actual vs predicted)
    actual_counts = pd.Series(y_test).value_counts().reindex(classes, fill_value=0)
    pred_counts   = pd.Series(y_pred).value_counts().reindex(classes, fill_value=0)
    x = np.arange(len(classes))
    width = 0.4
    fig, ax = plt.subplots(figsize=(max(10, len(classes) * 1.2), 5))
    ax.bar(x - width / 2, actual_counts, width, label="Actual",    color="steelblue")
    ax.bar(x + width / 2, pred_counts,   width, label="Predicted", color="tomato")
    ax.set_xticks(x)
    ax.set_xticklabels(classes, rotation=45, ha="right")
    ax.set_ylabel("Count")
    ax.set_title("Class Distribution — Actual vs Predicted (test set)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(plots_dir / "class_distribution.png", dpi=150)
    plt.close(fig)
    print(f"  class_distribution.png")

    # 4. Per-class precision / recall / f1
    report = classification_report(y_test, y_pred, labels=classes, output_dict=True, zero_division=0)
    metrics = {c: report[c] for c in classes if c in report}
    df_metrics = pd.DataFrame(metrics, index=["precision", "recall", "f1-score"]).T
    fig, ax = plt.subplots(figsize=(max(10, len(classes) * 1.2), 5))
    df_metrics[["precision", "recall", "f1-score"]].plot(kind="bar", ax=ax, colormap="tab10")
    ax.set_xticklabels(classes, rotation=45, ha="right")
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("Score")
    ax.set_title("Per-class Precision / Recall / F1")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(plots_dir / "per_class_metrics.png", dpi=150)
    plt.close(fig)
    print(f"  per_class_metrics.png")


def train(args) -> None:
    print(f"Loading dataset(s) from: {args.dataset}")
    if args.sample_frac:
        print(f"Sampling {args.sample_frac*100:.0f}% of each file")

    X, y = load_dataset(args.dataset, args.sample_frac)

    exclude = build_exclude_list(args)
    if exclude:
        X = drop_excluded(X, exclude)

    X, y = undersample_benign(X, y, args.benign_frac)

    print(f"\nTotal samples: {len(X):,}  |  Features: {X.shape[1]}")
    print("Class distribution:")
    for label, count in y.value_counts().items():
        print(f"  {label:<40} {count:>8,}")

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
        max_samples=0.7,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_sc, y_train)

    y_pred = model.predict(X_test_sc)
    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred, digits=4))

    for path_str in (args.model_out, args.scaler_out, args.features_out):
        Path(path_str).parent.mkdir(parents=True, exist_ok=True)

    with open(args.model_out, "wb") as f:
        pickle.dump(model, f)
    with open(args.scaler_out, "wb") as f:
        pickle.dump(scaler, f)
    with open(args.features_out, "w", encoding="utf-8") as f:
        json.dump(X.columns.tolist(), f, indent=2)

    print(f"\nSaved model    → {args.model_out}")
    print(f"Saved scaler   → {args.scaler_out}")
    print(f"Saved features → {args.features_out}")

    print(f"\nGenerating plots → {args.plots_out}/")
    save_plots(model, X_test_sc, y_test, y_pred, X.columns.tolist(), Path(args.plots_out))
    print("Done.")


if __name__ == "__main__":
    train(build_parser().parse_args())
