FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /loki-alert-lines .

FROM scratch
COPY --from=build /loki-alert-lines /loki-alert-lines
USER 65534:65534
EXPOSE 9097
ENTRYPOINT ["/loki-alert-lines"]
