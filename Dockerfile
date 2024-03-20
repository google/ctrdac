# This is a [distroless](https://github.com/GoogleContainerTools/distroless?tab=readme-ov-file#examples-with-docker)
# container image that contains acjs and slsa-verifier

FROM golang:bookworm AS build

ENV CGO_ENABLED=0
ENV GOOS=linux

RUN go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.4.1

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o acjs .


FROM gcr.io/distroless/static-debian12

WORKDIR /usr/local/bin
COPY --from=build /app/acjs .
COPY --from=build /go/bin/slsa-verifier .
ENTRYPOINT ["/usr/local/bin/acjs"]

