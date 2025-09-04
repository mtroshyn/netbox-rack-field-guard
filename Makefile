.PHONY: help install test lint format type-check clean build

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	poetry install --with dev

test: ## Run tests
	poetry run pytest

test-cov: ## Run tests with coverage
	poetry run pytest --cov=rack_field_guard --cov-report=html --cov-report=term

lint: ## Run linting
	poetry run flake8 rack_field_guard tests

format: ## Format code with black
	poetry run black rack_field_guard tests

type-check: ## Run type checking with mypy
	poetry run mypy rack_field_guard

check: lint type-check test ## Run all checks

clean: ## Clean build artifacts
	rm -rf .coverage
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

build: ## Build package
	poetry build

publish: ## Publish to PyPI (requires authentication)
	poetry publish

dev-setup: install ## Set up development environment
	@echo "Development environment ready!"
	@echo "Run 'make test' to run tests"
	@echo "Run 'make check' to run all checks"
