FROM golang:1.15-alpine AS build
LABEL org.opencontainers.image.source https://github.com/oviva-ag/apnvalidator

WORKDIR /src/
COPY . /src/
RUN go mod download
RUN CGO_ENABLED=0 go build -o /bin/apnvalidator

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /bin/apnvalidator /bin/apnvalidator
ENTRYPOINT ["/bin/apnvalidator"]
