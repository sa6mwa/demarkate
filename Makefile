GOOS = $(shell uname -s | tr '[:upper:]' '[:lower:]')
GOARCH = amd64
GO = CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go
MODULE = github.com/sa6mwa/demarkate
SRC = $(MODULE)/cmd/demarkate
BINDIR = bin
OUTPUT = $(BINDIR)/demarkate
DESTDIR = /usr/local/bin
VERSION = $(shell git describe --tags 2>/dev/null || echo v0.0)

.PHONY: all build dependencies clean install

all: clean build

build: dependencies $(OUTPUT)

dependencies:
	$(GO) get -v -d ./...

$(BINDIR):
	mkdir $(BINDIR)

$(OUTPUT): $(BINDIR)
	$(GO) build -v -ldflags "-X github.com/sa6mwa/demarkate.version=$(VERSION)" -o $(OUTPUT) $(SRC)

go.mod:
	go mod init $(MODULE)
	go mod tidy

clean:
	rm -f $(OUTPUT)
	test -d $(BINDIR) && rmdir $(BINDIR) || true

install: $(OUTPUT)
	install $(OUTPUT) $(DESTDIR)

docker: $(OUTPUT)
	docker build -t demarkate:$(VERSION) .

docker-run: $(OUTPUT)
	docker run -u $(shell id -u):$(shell -d -g) -ti --rm \
	-e DEMARKATE_SELF_SIGN=true \
	-e DEMARKATE_LISTEN_TO="localhost:8080" \
	-e DEMARKATE_BACKEND="http://localhost:55001" \
	demarkate:$(VERSION)

certandkey.pem:
	openssl req -x509 -sha256 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 \
	-subj "/C=SE/ST=Sweden/L=Gothenburg/O=Acme AB/OU=IT/CN=localhost"
	cat cert.pem key.pem > certandkey.pem
