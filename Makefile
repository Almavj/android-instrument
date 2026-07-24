PYTHON ?= python3

setup:
	./setup.sh

test:
	pytest -q

lint:
	flake8 .

clean:
	$(PYTHON) cleanup.py

run:
	./run_pipeline.sh $(APK)

docker-build:
	docker build -t android-instrumentor .

docker-run:
	docker run -v $(pwd)/output:/app/output android-instrumentor
