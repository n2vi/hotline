LOCAL_DIR := $(shell eval pwd)


all:
	echo
build:
	@echo "[+] Building..."
	@go build

	@echo "[+] Done"
		
clean:
	rm -f hotline


