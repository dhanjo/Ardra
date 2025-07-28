# syntax=docker/dockerfile:1
FROM golang:1.24.0-alpine AS build
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o ardra-fetcher

FROM alpine:3.19
WORKDIR /app
COPY --from=build /app/ardra-fetcher .
EXPOSE 8080
ENV PORT=8080
CMD ["./ardra-fetcher"] 