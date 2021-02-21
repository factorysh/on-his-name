build: bin
	go build -o bin/on-his-name main.go

bin:
	mkdir -p bin

dig:
	dig @localhost -p 1053 CH version.bind TXT
