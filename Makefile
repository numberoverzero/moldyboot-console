.PHONY: clean local production develop serve

clean:
	rm -rf build
	rm -rf dist

local:
	bin/compile-templates --dst build --mode local
	bin/compress-server --src build/local --dst dist/local.tar.gz

production:
	bin/compile-templates --dst build --mode production
	bin/compress-server --src build/production --dst dist/server.tar.gz

develop:
	pip install -r requirements.txt

serve: local
	bin/serve-local --src build/local
