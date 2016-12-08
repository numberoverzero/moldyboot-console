.PHONY: clean templates local production develop

clean:
	rm -rf build
	rm -rf dist

templates: clean
	bin/compile-templates --src src --dst build --mode local

local: templates
	bin/serve-local --src build/local

production: clean
	bin/compile-templates --src src --dst build --mode production
	bin/compress-server --src build/production --dst dist/server.tar.gz

develop:
	pip install -r requirements.txt