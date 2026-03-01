"""
CLI training script for the Network Intrusion Detector.

Usage
-----
# Train with default NSL-KDD URLs and save the model:
    python train.py

# Train in binary mode (normal vs attack):
    python train.py --binary

# Use local dataset files:
    python train.py --train path/to/KDDTrain+.txt --test path/to/KDDTest+.txt

# Specify output path for saved model:
    python train.py --output my_model.joblib
"""

import argparse

from intrusion_detector import (
    NetworkIntrusionDetector,
    _TRAIN_URL,
    _TEST_URL,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train and evaluate a Network Intrusion Detection model."
    )
    parser.add_argument(
        "--train",
        default=_TRAIN_URL,
        help="Path or URL to the training CSV (default: NSL-KDD KDDTrain+).",
    )
    parser.add_argument(
        "--test",
        default=_TEST_URL,
        help="Path or URL to the test CSV (default: NSL-KDD KDDTest+).",
    )
    parser.add_argument(
        "--binary",
        action="store_true",
        help="Binary classification: normal vs. attack (default: multi-class).",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Number of trees in the Random Forest (default: 100).",
    )
    parser.add_argument(
        "--output",
        default="intrusion_detector.joblib",
        help="Where to save the trained model (default: intrusion_detector.joblib).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    detector = NetworkIntrusionDetector(
        binary=args.binary,
        n_estimators=args.n_estimators,
    )

    train_df, test_df = detector.load_data(
        train_source=args.train,
        test_source=args.test,
    )

    detector.fit(train_df)
    detector.evaluate(test_df)
    detector.save(args.output)


if __name__ == "__main__":
    main()
