FROM alpine:3.23 AS certs
RUN apk add -U --no-cache ca-certificates

FROM golang:1.26.2-alpine3.23 AS build
WORKDIR /work
COPY go.mod* go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -tags netgo -ldflags '-w -extldflags "-static"' -o /build-out/ .

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /build-out/* /usr/bin/
WORKDIR /cloudbees/home
ENV HOME=/cloudbees/home
ENV PATH=/usr/bin
ENTRYPOINT ["configure-aws-credentials"]
