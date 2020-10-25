
FROM golang:1.15 as build

WORKDIR /go/src/github.com/pvtmert/ecrprxy

COPY ./ ./

ARG CGO_ENABLED=0
RUN go build
RUN go install

FROM scratch
COPY --from=build /go/bin/ecrprxy /ecrprxy
ENTRYPOINT [ "/ecrprxy" ]
