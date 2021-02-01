package uk.ac.ox.softeng.maurodatamapper.plugin.authentication.keycloak

/**
 * @since 03/02/2021
 */
class KeycloakDetails {
    String emailAddress
    String username
    String keycloakPassword
    String mdmPassword

    Map getKeycloakLoginCredentials() {
        [
            username: emailAddress,
            password: keycloakPassword
        ]
    }

    Map getMdmLoginCredentials() {
        [
            username: emailAddress,
            password: mdmPassword
        ]
    }
}
