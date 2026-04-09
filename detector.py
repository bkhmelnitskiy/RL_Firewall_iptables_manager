

import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

from column_mapping import map_output_columns


_PROTO_MAP = {6: "tcp", 17: "udp"}


class MLDetector:
    def __init__(
        self,
        model_path:    str | Path = "artifacts/model.pkl",
        scaler_path:   str | Path = "artifacts/scaler.pkl",
        features_path: str | Path = "artifacts/feature_order.json",
    ):
        with open(model_path, "rb") as f:
            self._model = pickle.load(f)
        with open(scaler_path, "rb") as f:
            self._scaler = pickle.load(f)
        with open(features_path, "r", encoding="utf-8") as f:
            self._features: list[str] = json.load(f)

    def predict(self, df: pd.DataFrame) -> pd.Series:
        mapped  = map_output_columns(df)
        aligned = mapped.reindex(columns=self._features, fill_value=0)
        aligned = aligned.apply(pd.to_numeric, errors="coerce")
        aligned = aligned.replace([np.inf, -np.inf], np.nan).fillna(0)
        preds   = self._model.predict(self._scaler.transform(aligned))
        return pd.Series(preds, index=df.index)

    def check(self, df: pd.DataFrame) -> list[dict]:
        if df.empty:
            return []

        labels  = self.predict(df)
        attacks: list[dict] = []

        for idx, label in labels.items():
            if str(label).upper() == "BENIGN":
                continue
            row       = df.loc[idx]
            proto_num = int(row.get("protocol", 6))
            attacks.append({
                "src_ip":   str(row["src_ip"]).strip(),
                "dst_ip":   str(row["dst_ip"]).strip(),
                "dst_port": int(row.get("dst_port", 0)),
                "protocol": _PROTO_MAP.get(proto_num, "tcp"),
                "label":    str(label).strip(),
                "reason":   "ml",
            })

        return attacks
