# Makefile

.PHONY: all clean init build-py build-go build

all: build

init:
	python3 -m venv venv
	./venv/bin/pip install -r requirements.txt

build-py: init
	./venv/bin/pyinstaller --onefile --distpath ./bin --workpath ./build python/orchestrator.py

build-go:
	go build -o bin/threat-sim cmd/mcp-server/main.go

build: build-py build-go

clean:
	rm -rf bin/ build/ __pycache__/ python/__pycache__/ *.spec .threatmodel.json
