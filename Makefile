.PHONY: help venv install install-dev test lint format clean

PYTHON := python3
VENV := .venv
BIN := $(VENV)/bin

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

venv:  ## Create virtual environment
	$(PYTHON) -m venv $(VENV)
	@echo "Virtual environment created. Activate with: source $(VENV)/bin/activate"

install: venv  ## Install dependencies
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e .

install-dev: venv  ## Install development dependencies
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

test:  ## Run tests
	$(BIN)/pytest

test-cov:  ## Run tests with coverage report
	$(BIN)/pytest --cov=src --cov-report=html

lint:  ## Run linters
	$(BIN)/flake8 src tests
	$(BIN)/mypy src

format:  ## Format code
	$(BIN)/black src tests
	$(BIN)/isort src tests

format-check:  ## Check code formatting
	$(BIN)/black --check src tests
	$(BIN)/isort --check-only src tests

clean:  ## Clean up generated files
	rm -rf $(VENV)
	rm -rf *.egg-info
	rm -rf dist
	rm -rf build
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf htmlcov
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
