#!/usr/bin/env bash

rm gocert
GOOS=linux GOARCH=386 go build .

scp gocert zuul:/tmp/gocert

ssh zuul sudo supervisorctl stop gocert
ssh zuul sudo cp /tmp/gocert /usr/local/bin/gocert
ssh zuul sudo supervisorctl start gocert