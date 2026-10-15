.PHONY: install test lint demo redteam mcp docker

install:
	pip install -e ".[dev,all]"

test:
	pytest -q

lint:
	ruff check src tests

demo:
	opsguard investigate --mock -s payments-crashloop

redteam:
	opsguard redteam --fail-above 0.0 --out reports

mcp:
	opsguard mcp -s payments-crashloop

docker:
	docker build -t opsguard:local .
