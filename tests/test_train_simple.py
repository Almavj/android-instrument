import json
import os
import tempfile
import unittest
from pathlib import Path

import numpy as np


class TestLoadXY(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="train-test-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_features(self, samples, feature_names=None):
        if feature_names is None:
            feature_names = ["feat_a", "feat_b", "feat_c"]
        data = {"feature_names": feature_names, "samples": samples}
        path = os.path.join(self.tmp, "features.json")
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    def test_load_basic(self):
        from train_simple import load_xy
        path = self._write_features([
            {"label": "benign", "features": {"feat_a": 1.0, "feat_b": 0.0, "feat_c": 0.5}},
            {"label": "malware", "features": {"feat_a": 0.0, "feat_b": 2.0, "feat_c": 1.0}},
        ])
        names, X, y = load_xy(path)
        self.assertEqual(len(names), 3)
        self.assertEqual(X.shape, (2, 3))
        self.assertEqual(list(y), ["benign", "malware"])

    def test_load_missing_features_default_zero(self):
        from train_simple import load_xy
        path = self._write_features([
            {"label": "a", "features": {"feat_a": 5.0}},
        ])
        names, X, y = load_xy(path)
        self.assertAlmostEqual(X[0][0], 5.0)
        self.assertAlmostEqual(X[0][1], 0.0)  # missing feat_b
        self.assertAlmostEqual(X[0][2], 0.0)  # missing feat_c


class TestSynthAugment(unittest.TestCase):
    def test_augment_doubles_minimum(self):
        from train_simple import synth_augment
        X = np.array([[1.0, 2.0, 3.0]])
        y = np.array(["benign"])
        X_out, y_out = synth_augment(X, y, n_per_class=5, seed=0)
        # original 1 + 5 benign + 5 malware = 11
        self.assertEqual(len(X_out), 11)
        self.assertIn("synth:benign", set(y_out))
        self.assertIn("synth:malware", set(y_out))

    def test_empty_input(self):
        from train_simple import synth_augment
        X = np.array([]).reshape(0, 3)
        y = np.array([])
        X_out, y_out = synth_augment(X, y, n_per_class=5)
        self.assertEqual(len(X_out), 0)


class TestTrainSimpleIntegration(unittest.TestCase):
    def test_minimal_two_class_train(self):
        from train_simple import load_xy
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        import joblib

        tmp = tempfile.mkdtemp(prefix="train-integ-")
        try:
            data = {
                "feature_names": ["f1", "f2", "f3"],
                "samples": [
                    {"label": "benign", "features": {"f1": 0.1, "f2": 0.2, "f3": 0.3}},
                    {"label": "benign", "features": {"f1": 0.15, "f2": 0.25, "f3": 0.35}},
                    {"label": "malware", "features": {"f1": 5.0, "f2": 6.0, "f3": 7.0}},
                    {"label": "malware", "features": {"f1": 5.5, "f2": 6.5, "f3": 7.5}},
                ],
            }
            path = os.path.join(tmp, "features.json")
            with open(path, "w") as f:
                json.dump(data, f)

            names, X, y = load_xy(path)
            self.assertEqual(len(set(y)), 2)

            clf = RandomForestClassifier(n_estimators=10, random_state=42)
            clf.fit(X, y)
            preds = clf.predict(X)
            # On training data with clear separation, should get all right
            self.assertEqual(list(preds), list(y))
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
