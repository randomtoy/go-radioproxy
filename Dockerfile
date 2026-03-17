FROM golang:1.23-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w' -o /out/stream-proxy ./cmd/stream-proxy

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /out/stream-proxy /app/stream-proxy
COPY --from=builder /src/users.yaml /app/users.yaml

ENV PORT=8080
ENV USERS_FILE=/app/users.yaml

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/app/stream-proxy"]
