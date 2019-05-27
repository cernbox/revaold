all:
	docker build -t cbox_rpm_builder_img .
	docker run --rm -it -v ${CURDIR}:/root/go/src/github.com/cernbox/revaold -w /root/go/src/github.com/cernbox/revaold cbox_rpm_builder_img bash -lc "make rpm"

rpm:
	go get ./...
	go build ./...
	chown -R root:root .
	cd revad && make rpm
	cd ocproxy && make rpm
