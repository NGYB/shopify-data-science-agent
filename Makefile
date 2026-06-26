# Makefile for Shopify Data Science Agent

.PHONY: install playground lint test

install:
	@echo "Installing project dependencies..."
	agents-cli install

playground:
	@echo "Launching the ADK local playground..."
	agents-cli playground

lint:
	@echo "Running lint and quality checks..."
	agents-cli lint

test:
	@echo "Running lint checks and tests..."
	agents-cli lint
