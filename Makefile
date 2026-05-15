.PHONY: test build clean

test:
	opa test policy/ data/ tests/ -v

build: test
	mkdir -p build
	opa build \
		--signing-key keys/bundle-signing.pem \
		--signing-alg RS256 \
		--bundle policy \
		--bundle data \
		--output build/bundle.tar.gz
	@echo "Bundle built: build/bundle.tar.gz"

clean:
	rm -rf build/
