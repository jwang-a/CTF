#!/bin/bash

docker build . -t cobolstrike-build
docker run -v ./:/root/:rw --rm cobolstrike-build
docker rmi cobolstrike-build
