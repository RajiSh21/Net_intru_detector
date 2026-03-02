"""
Network Intrusion Detection System using the NSL-KDD dataset.

Trains a Random Forest classifier to distinguish normal traffic from
four attack families: DoS, Probe, R2L, and U2R.
"""

import io
import urllib.request
from typing import Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder, StandardScaler

# ------------------------------------------------------------------
# NSL-KDD dataset URLs (GitHub mirror)
# ------------------------------------------------------------------
_TRAIN_URL = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
)
_TEST_URL = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"
)

# Column names from the NSL-KDD specification
COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "attack_type", "difficulty",
]

# Categorical columns that require encoding
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

# Map specific attack names to their family
_ATTACK_MAP = {
    "normal": "normal",
    # DoS
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "apache2": "DoS",
    "udpstorm": "DoS", "processtable": "DoS", "mailbomb": "DoS",
    # Probe
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "satan": "Probe", "mscan": "Probe", "saint": "Probe",
    # R2L (Remote-to-Local)
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L",
    "multihop": "R2L", "phf": "R2L", "spy": "R2L",
    "warezclient": "R2L", "warezmaster": "R2L", "sendmail": "R2L",
    "named": "R2L", "snmpgetattack": "R2L", "snmpguess": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "httptunnel": "R2L",
    # U2R (User-to-Root)
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R",
    "rootkit": "U2R", "sqlattack": "U2R", "xterm": "U2R", "ps": "U2R",
}


def _load_csv(source: str) -> pd.DataFrame:
    """Load a NSL-KDD CSV from a file path or URL."""
    if source.startswith("http://") or source.startswith("https://"):
        with urllib.request.urlopen(source, timeout=30) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8")
        df = pd.read_csv(io.StringIO(raw), header=None, names=COLUMN_NAMES)
    else:
        df = pd.read_csv(source, header=None, names=COLUMN_NAMES)
    return df


class NetworkIntrusionDetector:
    """Binary/multi-class network intrusion detector.

    Parameters
    ----------
    binary : bool
        When True the model predicts *normal* vs *attack*.
        When False it predicts the attack family
        (normal / DoS / Probe / R2L / U2R).
    n_estimators : int
        Number of trees in the Random Forest.
    random_state : int
        Seed for reproducibility.
    """

    def __init__(
        self,
        binary: bool = False,
        n_estimators: int = 100,
        random_state: int = 42,
    ):
        self.binary = binary
        self.n_estimators = n_estimators
        self.random_state = random_state

        self._model = RandomForestClassifier(
            n_estimators=n_estimators,
            n_jobs=-1,
            random_state=random_state,
        )
        self._scaler = StandardScaler()
        self._label_encoders: dict[str, LabelEncoder] = {}
        self._fitted = False

    # ------------------------------------------------------------------
    # Data helpers
    # ------------------------------------------------------------------

    def _map_labels(self, df: pd.DataFrame) -> pd.Series:
        """Return target labels derived from *attack_type*."""
        families = df["attack_type"].str.lower().map(_ATTACK_MAP).fillna("unknown")
        if self.binary:
            return (families != "normal").astype(int).rename("label")
        return families.rename("label")

    def _encode_features(self, df: pd.DataFrame, fit: bool = False) -> np.ndarray:
        """Encode categoricals and scale numerics."""
        data = df.drop(columns=["attack_type", "difficulty"], errors="ignore").copy()

        for col in CATEGORICAL_COLS:
            if col not in data.columns:
                continue
            le = self._label_encoders.get(col)
            if fit or le is None:
                le = LabelEncoder()
                le.fit(data[col].astype(str))
                self._label_encoders[col] = le
            # Handle unseen categories gracefully
            known = set(le.classes_)
            # Map unseen categories to the first known class as a safe fallback
            data[col] = data[col].astype(str).apply(
                lambda v, k=known: v if v in k else le.classes_[0]
            )
            data[col] = le.transform(data[col])

        X = data.values.astype(float)
        if fit:
            X = self._scaler.fit_transform(X)
        else:
            X = self._scaler.transform(X)
        return X

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_data(
        self,
        train_source: str = _TRAIN_URL,
        test_source: str = _TEST_URL,
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        """Download / read train and test DataFrames.

        Parameters
        ----------
        train_source : str
            File path or URL to the training CSV.
        test_source : str
            File path or URL to the test CSV.

        Returns
        -------
        tuple[pd.DataFrame, pd.DataFrame]
            ``(train_df, test_df)``
        """
        print("Loading training data …")
        train_df = _load_csv(train_source)
        print(f"  {len(train_df):,} training samples loaded.")
        print("Loading test data …")
        test_df = _load_csv(test_source)
        print(f"  {len(test_df):,} test samples loaded.")
        return train_df, test_df

    def fit(self, train_df: pd.DataFrame) -> "NetworkIntrusionDetector":
        """Train the detector on *train_df*.

        Parameters
        ----------
        train_df : pd.DataFrame
            DataFrame with NSL-KDD columns (including *attack_type*).

        Returns
        -------
        self
        """
        y = self._map_labels(train_df)
        X = self._encode_features(train_df, fit=True)
        print(
            f"Training Random Forest ({self.n_estimators} trees, "
            f"{'binary' if self.binary else 'multi-class'}) …"
        )
        self._model.fit(X, y)
        self._fitted = True
        print("Training complete.")
        return self

    def evaluate(self, test_df: pd.DataFrame) -> dict:
        """Evaluate the model and print a classification report.

        Parameters
        ----------
        test_df : pd.DataFrame
            DataFrame with NSL-KDD columns (including *attack_type*).

        Returns
        -------
        dict
            ``{"report": str, "confusion_matrix": np.ndarray}``
        """
        if not self._fitted:
            raise RuntimeError("Call fit() before evaluate().")
        y_true = self._map_labels(test_df)
        X = self._encode_features(test_df, fit=False)
        y_pred = self._model.predict(X)
        report = classification_report(y_true, y_pred, zero_division=0)
        cm = confusion_matrix(y_true, y_pred)
        print("\nClassification Report:\n")
        print(report)
        return {"report": report, "confusion_matrix": cm}

    def predict(self, sample: Union[dict, pd.DataFrame]) -> np.ndarray:
        """Predict whether a network sample is normal or an attack.

        Parameters
        ----------
        sample : dict or pd.DataFrame
            A single record (dict) or a DataFrame of records.
            Must contain the 41 NSL-KDD feature columns
            (without *attack_type* / *difficulty*).

        Returns
        -------
        np.ndarray
            Predicted label(s).
        """
        if not self._fitted:
            raise RuntimeError("Call fit() before predict().")
        if isinstance(sample, dict):
            df = pd.DataFrame([sample])
        else:
            df = sample.copy()
        X = self._encode_features(df, fit=False)
        return self._model.predict(X)

    def predict_proba(self, sample: Union[dict, pd.DataFrame]) -> np.ndarray:
        """Return class probabilities for each sample.

        Parameters
        ----------
        sample : dict or pd.DataFrame
            Same format as :meth:`predict`.

        Returns
        -------
        np.ndarray
            Shape ``(n_samples, n_classes)``.
        """
        if not self._fitted:
            raise RuntimeError("Call fit() before predict_proba().")
        if isinstance(sample, dict):
            df = pd.DataFrame([sample])
        else:
            df = sample.copy()
        X = self._encode_features(df, fit=False)
        return self._model.predict_proba(X)

    def save(self, path: str = "intrusion_detector.joblib") -> None:
        """Persist the trained detector to *path*."""
        if not self._fitted:
            raise RuntimeError("Call fit() before save().")
        joblib.dump(self, path)
        print(f"Model saved to {path}")

    @staticmethod
    def load(path: str = "intrusion_detector.joblib") -> "NetworkIntrusionDetector":
        """Load a previously saved detector from *path*."""
        detector = joblib.load(path)
        print(f"Model loaded from {path}")
        return detector
