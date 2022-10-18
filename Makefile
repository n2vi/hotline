LOCAL_DIR := $(shell eval pwd)
USER := $(shell eval whoami)
NUM := $(shell eval shuf -i10000000000-19999999999 -n1)

all:
	echo
build:
	@echo "[+] Building..."
	@go build

	@echo "[+] Done"

setup:
	@echo "[+] Setting up"
	echo '{"$(USER)": $(NUM), "Peers":[]}' > PrincipalsDB
	echo '{}' > keyCount
	mkdir -p archiveDB
		
install:
	@echo "[+] Build & Install..."
	@go install

	@echo "[+] Done"
clean:
	rm -f hotline
nuke: clean
	rm -rf archiveDB
	rm -f keyCount
	rm -f PrincipalsDB


