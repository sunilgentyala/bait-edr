.PHONY: install test lint validate demo run serve diagrams diagrams-check site verify clean

install:
	python -m pip install -e ".[dev]"

test:
	pytest --cov=bait_edr --cov-report=term-missing --cov-fail-under=75

lint:
	ruff check .

validate:
	bait validate-rules --rules rules/builtin.yml

demo:
	bait demo

run:
	bait run --once

serve:
	bait serve

diagrams:
	python scripts/render_diagrams.py

diagrams-check:
	python scripts/render_diagrams.py --check

site:
	python scripts/validate_site.py

verify: lint test validate diagrams-check site
	python -m compileall -q bait_edr tests scripts

clean:
	rm -rf .coverage .pytest_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
