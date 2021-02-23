build: bin
	go build -o bin/on-his-name main.go

bin:
	mkdir -p bin

# be modern use drill is available
DRILL := $(shell drill -v 2> /dev/null)
ARGS := @localhost -p 1053 CH version.bind TXT
dig:
ifdef DRILL
	drill $(ARGS)
else
	dig $(ARGS)
endif
