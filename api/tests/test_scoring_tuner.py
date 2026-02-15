"""Tests for scoring tuner weight management."""
import json
import os
import pytest

from api.routers.scoring import _normalize_weights, _load_weights, _save_weights, DEFAULT_WEIGHTS, WEIGHTS_FILE


class TestWeightNormalization:
    def test_already_normalized(self):
        weights = {"beacon": 0.3, "dns_threat": 0.25, "ids_alert": 0.25, "long_connection": 0.2}
        result = _normalize_weights(weights)
        total = sum(result.values())
        assert abs(total - 1.0) < 0.001

    def test_unnormalized_weights(self):
        weights = {"beacon": 50, "dns_threat": 30, "ids_alert": 10, "long_connection": 10}
        result = _normalize_weights(weights)
        total = sum(result.values())
        assert abs(total - 1.0) < 0.001
        assert result["beacon"] == 0.5

    def test_zero_weights_returns_defaults(self):
        weights = {"beacon": 0, "dns_threat": 0, "ids_alert": 0, "long_connection": 0}
        result = _normalize_weights(weights)
        assert result == DEFAULT_WEIGHTS

    def test_single_category_gets_full_weight(self):
        weights = {"beacon": 1.0, "dns_threat": 0, "ids_alert": 0, "long_connection": 0}
        result = _normalize_weights(weights)
        assert result["beacon"] == 1.0

    def test_equal_weights(self):
        weights = {"beacon": 1, "dns_threat": 1, "ids_alert": 1, "long_connection": 1}
        result = _normalize_weights(weights)
        assert result["beacon"] == 0.25


class TestWeightPersistence:
    def setup_method(self):
        """Clean up weights file before each test."""
        if os.path.exists(WEIGHTS_FILE):
            os.remove(WEIGHTS_FILE)

    def teardown_method(self):
        """Clean up after tests."""
        if os.path.exists(WEIGHTS_FILE):
            os.remove(WEIGHTS_FILE)

    def test_load_defaults_when_no_file(self):
        result = _load_weights()
        assert result == DEFAULT_WEIGHTS

    def test_save_and_load(self):
        custom = {"beacon": 0.5, "dns_threat": 0.2, "ids_alert": 0.2, "long_connection": 0.1}
        _save_weights(custom)
        result = _load_weights()
        assert result == custom

    def test_save_creates_directory(self):
        custom = {"beacon": 0.4, "dns_threat": 0.3, "ids_alert": 0.2, "long_connection": 0.1}
        _save_weights(custom)
        assert os.path.exists(WEIGHTS_FILE)


class TestDefaultWeights:
    def test_defaults_sum_to_one(self):
        total = sum(DEFAULT_WEIGHTS.values())
        assert abs(total - 1.0) < 0.001

    def test_defaults_have_all_categories(self):
        assert "beacon" in DEFAULT_WEIGHTS
        assert "dns_threat" in DEFAULT_WEIGHTS
        assert "ids_alert" in DEFAULT_WEIGHTS
        assert "long_connection" in DEFAULT_WEIGHTS

    def test_all_defaults_positive(self):
        for v in DEFAULT_WEIGHTS.values():
            assert v > 0
