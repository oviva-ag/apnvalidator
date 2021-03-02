FROM golang:1.15-alpine AS build
LABEL org.opencontainers.image.source https://github.com/oviva-ag/apnvalidator

WORKDIR /src/
COPY . /src/
RUN go mod download
RUN go build -o /bin/apnvalidator

FROM alpine
COPY --from=build /bin/apnvalidator /bin/apnvalidator
ENTRYPOINT ["/bin/apnvalidator"]
