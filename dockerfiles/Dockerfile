FROM jboss/keycloak

COPY ./realms /tmp/realms

ENV KEYCLOAK_USER=admin \
    KEYCLOAK_PASSWORD=password \
    PROXY_ADDRESS_FORWARDING=true \
    KEYCLOAK_IMPORT=/tmp/realms/test_realm.json