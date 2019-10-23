pwd = $(shell pwd)

default: all
on:
	GO11MODULE=on
all: on
	docker build -t cbox_rpm_builder_img .
	docker run --rm -it -v ${pwd}:/root/revaold cbox_rpm_builder_img bash -lc "find && cd /root/revaold && make rpm"

rpm: on
	cd revad && go build
	cd ocproxy && go build
	chown -R root:root .
	cd revad && make rpm
	cd ocproxy && make rpm
