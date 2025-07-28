FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o /main main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /main .

RUN apk add --no-cache nmap nmap-scripts nmap-nselibs

EXPOSE 8082
EXPOSE 8083
EXPOSE 8084
EXPOSE 8085
EXPOSE 8086
EXPOSE 8087
EXPOSE 8088
EXPOSE 8089

CMD ["/app/main"] 