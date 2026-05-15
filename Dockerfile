FROM golang:latest AS builder
WORKDIR /app
COPY . .
# Matikan CGO agar binary bersifat statis (bisa jalan di Alpine)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a -installsuffix cgo -o p2p-node ./cmd/node

FROM alpine:latest
WORKDIR /app
# Tambahkan sertifikat CA agar bisa koneksi HTTPS jika diperlukan
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/p2p-node .
RUN mkdir -p /data
ENTRYPOINT ["./p2p-node"]
