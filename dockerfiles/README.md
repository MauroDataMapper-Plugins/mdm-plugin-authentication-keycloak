# Setting up Keycloak Server Test Environment

## Build the Keycloak Docker image

```bash
$ docker build --tag=keycloak-mdm:latest .
```

This will build an image with the test realm imported on startup

## Start the Keycloak Docker Instance

Use `./start-keycloak.sh`