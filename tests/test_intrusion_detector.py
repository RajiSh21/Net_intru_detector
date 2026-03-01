"""
Tests for the NetworkIntrusionDetector.

Run with:  python -m pytest tests/ -v
"""

import numpy as np
import pandas as pd
import pytest

from intrusion_detector import (
    CATEGORICAL_COLS,
    COLUMN_NAMES,
    NetworkIntrusionDetector,
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_df(n: int = 50, seed: int = 0) -> pd.DataFrame:
    """Create a minimal synthetic NSL-KDD-shaped DataFrame."""
    rng = np.random.default_rng(seed)

    protocols = ["tcp", "udp", "icmp"]
    services = ["http", "ftp", "smtp", "other", "private"]
    flags = ["SF", "S0", "REJ", "RSTO"]
    attacks = ["normal", "neptune", "ipsweep", "buffer_overflow", "ftp_write"]

    rows = []
    for i in range(n):
        row = {
            "duration": rng.integers(0, 1000),
            "protocol_type": protocols[i % len(protocols)],
            "service": services[i % len(services)],
            "flag": flags[i % len(flags)],
            "src_bytes": rng.integers(0, 50000),
            "dst_bytes": rng.integers(0, 50000),
            "land": int(rng.random() > 0.9),
            "wrong_fragment": rng.integers(0, 3),
            "urgent": rng.integers(0, 3),
            "hot": rng.integers(0, 30),
            "num_failed_logins": rng.integers(0, 5),
            "logged_in": int(rng.random() > 0.5),
            "num_compromised": rng.integers(0, 10),
            "root_shell": int(rng.random() > 0.95),
            "su_attempted": int(rng.random() > 0.95),
            "num_root": rng.integers(0, 5),
            "num_file_creations": rng.integers(0, 5),
            "num_shells": rng.integers(0, 3),
            "num_access_files": rng.integers(0, 5),
            "num_outbound_cmds": 0,
            "is_host_login": int(rng.random() > 0.95),
            "is_guest_login": int(rng.random() > 0.95),
            "count": rng.integers(0, 512),
            "srv_count": rng.integers(0, 512),
            "serror_rate": rng.random(),
            "srv_serror_rate": rng.random(),
            "rerror_rate": rng.random(),
            "srv_rerror_rate": rng.random(),
            "same_srv_rate": rng.random(),
            "diff_srv_rate": rng.random(),
            "srv_diff_host_rate": rng.random(),
            "dst_host_count": rng.integers(0, 255),
            "dst_host_srv_count": rng.integers(0, 255),
            "dst_host_same_srv_rate": rng.random(),
            "dst_host_diff_srv_rate": rng.random(),
            "dst_host_same_src_port_rate": rng.random(),
            "dst_host_srv_diff_host_rate": rng.random(),
            "dst_host_serror_rate": rng.random(),
            "dst_host_srv_serror_rate": rng.random(),
            "dst_host_rerror_rate": rng.random(),
            "dst_host_srv_rerror_rate": rng.random(),
            "attack_type": attacks[i % len(attacks)],
            "difficulty": rng.integers(1, 21),
        }
        rows.append(row)
    return pd.DataFrame(rows)


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

class TestNetworkIntrusionDetector:

    def test_binary_fit_predict_shape(self):
        df = _make_df(100)
        det = NetworkIntrusionDetector(binary=True, n_estimators=10)
        det.fit(df)
        preds = det.predict(df.drop(columns=["attack_type", "difficulty"]))
        assert preds.shape == (100,)
        assert set(preds).issubset({0, 1})

    def test_multiclass_fit_predict_shape(self):
        df = _make_df(100)
        det = NetworkIntrusionDetector(binary=False, n_estimators=10)
        det.fit(df)
        preds = det.predict(df.drop(columns=["attack_type", "difficulty"]))
        assert preds.shape == (100,)
        expected_classes = {"normal", "DoS", "Probe", "U2R", "R2L"}
        assert set(preds).issubset(expected_classes)

    def test_predict_dict_input(self):
        df = _make_df(50)
        det = NetworkIntrusionDetector(binary=True, n_estimators=10)
        det.fit(df)
        sample = df.drop(columns=["attack_type", "difficulty"]).iloc[0].to_dict()
        preds = det.predict(sample)
        assert preds.shape == (1,)

    def test_predict_proba_shape(self):
        df = _make_df(50)
        det = NetworkIntrusionDetector(binary=True, n_estimators=10)
        det.fit(df)
        proba = det.predict_proba(df.drop(columns=["attack_type", "difficulty"]))
        assert proba.shape[0] == 50
        assert proba.shape[1] == 2  # binary: normal / attack
        assert np.allclose(proba.sum(axis=1), 1.0)

    def test_evaluate_returns_report(self):
        df = _make_df(100)
        det = NetworkIntrusionDetector(binary=False, n_estimators=10)
        det.fit(df)
        result = det.evaluate(df)
        assert "report" in result
        assert "confusion_matrix" in result
        assert isinstance(result["report"], str)

    def test_save_and_load(self, tmp_path):
        df = _make_df(60)
        det = NetworkIntrusionDetector(binary=True, n_estimators=5)
        det.fit(df)
        path = str(tmp_path / "model.joblib")
        det.save(path)
        loaded = NetworkIntrusionDetector.load(path)
        preds_orig = det.predict(df.drop(columns=["attack_type", "difficulty"]))
        preds_loaded = loaded.predict(df.drop(columns=["attack_type", "difficulty"]))
        assert np.array_equal(preds_orig, preds_loaded)

    def test_not_fitted_raises(self):
        det = NetworkIntrusionDetector()
        with pytest.raises(RuntimeError, match="fit"):
            det.predict({"duration": 0, "protocol_type": "tcp"})

    def test_unseen_categorical_handled(self):
        df_train = _make_df(50)
        det = NetworkIntrusionDetector(binary=True, n_estimators=5)
        det.fit(df_train)

        # Create a sample with an unseen service value
        sample = df_train.drop(columns=["attack_type", "difficulty"]).iloc[0].copy()
        sample["service"] = "unknown_service_xyz"
        preds = det.predict(sample.to_dict())
        assert preds.shape == (1,)
