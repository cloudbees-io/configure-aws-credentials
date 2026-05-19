FROM alpine:3.23 AS certs
RUN apk add -U --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY configure-aws-credentials /usr/bin/
WORKDIR /cloudbees/home
ENV HOME=/cloudbees/home
ENV PATH=/usr/bin
ENTRYPOINT ["configure-aws-credentials"]
