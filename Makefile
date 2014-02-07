default:
	make -C src
	cp version core/version
	cp src/bbproxy core/bbproxy/bbproxy
	make -C core
	cp core/bbproxy-core.zip bbproxy-core-`cat version`.zip

source:
	make clean
	tar czf bbproxy-core-`cat version`.tar.gz -C .. --exclude bbproxy-core-`cat version`.tar.gz bbproxy

clean:
	make -C src clean
	make -C core clean
	rm -f bbproxy-core-*.zip
	rm -f bbproxy-core-*.tar.gz
