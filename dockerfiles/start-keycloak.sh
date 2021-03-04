#!/bin/bash

docker run --rm -d \
-p 8090:8080 \
--name keycloak \
keycloak-mdm:latest