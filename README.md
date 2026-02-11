# python-network-utils

Python-based utilities for network operations.

## Features

- HTTP client wrapper with session management
- URL validation and parsing utilities
- IP address validation

## Requirements

- Python 3.8+

## Installation

### Using venv (recommended)

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate     # Windows

# Install in development mode
pip install -e ".[dev]"
```

### Using Makefile

```bash
# Setup with development dependencies
make install-dev

# Or just production dependencies
make install
```

### Using setup script

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

## Usage

```python
from network_utils import HTTPClient, is_valid_url, parse_url

# Validate URL
print(is_valid_url("https://example.com"))  # True

# Parse URL
result = parse_url("https://example.com/path?query=value")
print(result)

# HTTP Client
with HTTPClient(base_url="https://api.example.com") as client:
    response = client.get("/users")
    print(response.json())
```

## Development

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage report
make test-cov

# Or directly with pytest
pytest
pytest --cov=src --cov-report=html
```

### Code Quality

```bash
# Format code
make format

# Run linters
make lint

# Check formatting without changes
make format-check
```

### Clean up

```bash
make clean
```

## Project Structure

```
python-network-utils/
├── src/
│   └── network_utils/
│       ├── __init__.py
│       ├── http_client.py
│       └── utils.py
├── tests/
│   ├── __init__.py
│   ├── test_http_client.py
│   └── test_utils.py
├── scripts/
│   └── setup.sh
├── .gitignore
├── LICENSE
├── Makefile
├── pyproject.toml
├── README.md
├── requirements.txt
└── requirements-dev.txt
```

## License

MIT License
