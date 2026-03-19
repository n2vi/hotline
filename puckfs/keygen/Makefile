go:
	go build
	./keygen > broker-secret 2> out
	sed 1q out | sh > puck-secret
clean:
	rm -f keygen out broker-secret puck-secret
