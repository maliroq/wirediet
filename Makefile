.PHONY: test vet build demo validate-local clean

test:
	go test ./...

vet:
	go vet ./...

build:
	go build -trimpath -o bin/wirediet ./cmd/wirediet

demo: build
	./bin/wirediet scan --input examples/synthetic/generic.csv --format csv --device 192.0.2.42 --out /tmp/wirediet-analysis.json

validate-local:
	python3 dev.py

clean:
	rm -rf bin .wirediet analysis.json analysis.public.json wirediet-policy final-policy
