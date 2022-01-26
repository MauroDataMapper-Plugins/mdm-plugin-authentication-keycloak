/*
 * Copyright 2020-2022 University of Oxford and Health and Social Care Information Centre, also known as NHS Digital
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package uk.ac.ox.softeng.maurodatamapper.plugin.authentication.keycloak


import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.test.functional.BaseFunctionalSpec

import grails.core.GrailsApplication
import grails.gorm.transactions.Transactional
import grails.testing.mixin.integration.Integration
import grails.testing.spock.OnceBefore
import groovy.util.logging.Slf4j
import spock.lang.Shared
import spock.lang.Stepwise

import static io.micronaut.http.HttpStatus.NO_CONTENT
import static io.micronaut.http.HttpStatus.OK
import static io.micronaut.http.HttpStatus.UNAUTHORIZED

/**
 * <pre>
 * Controller: authenticating
 * |  POST  | /api/admin/activeSessions  | Action: activeSessionsWithCredentials
 * |  *     | /api/authentication/logout | Action: logout
 * |  POST  | /api/authentication/login  | Action: login
 * </pre>
 * @see uk.ac.ox.softeng.maurodatamapper.security.authentication.AuthenticatingController
 */
@Slf4j
@Integration
@Stepwise
class AuthenticatingFunctionalSpec extends BaseFunctionalSpec {

    GrailsApplication grailsApplication

    CatalogueUserService catalogueUserService

    @Shared
    Map keycloakConfig

    @Shared
    KeycloakDetails adminDetails

    @Shared
    KeycloakDetails keycloakOnlyDetails

    @Shared
    KeycloakDetails mdmOnlyDetails

    @OnceBefore
    @Transactional
    def checkAndSetupData() {
        keycloakConfig = grailsApplication.config.keycloak as Map

        adminDetails = new KeycloakDetails(emailAddress: keycloakConfig.adminUser.emailAddress,
                                           keycloakPassword: keycloakConfig.adminUser.password,
                                           username: keycloakConfig.adminUser.username,
                                           mdmPassword: 'password')

        keycloakOnlyDetails = new KeycloakDetails(emailAddress: keycloakConfig.keycloakOnlyUser.emailAddress,
                                                  keycloakPassword: keycloakConfig.keycloakOnlyUser.password,
                                                  username: keycloakConfig.keycloakOnlyUser.username,
                                                  mdmPassword: null)

        mdmOnlyDetails = new KeycloakDetails(emailAddress: 'editor@test.com',
                                             keycloakPassword: null,
                                             username: null,
                                             mdmPassword: 'password')
    }

    @Transactional
    void deleteUser(String id) {
        catalogueUserService.get(id).delete(flush: true)
    }

    @Override
    String getResourcePath() {
        'authentication'
    }

    void 'A01 : test logging in as user who exists in both keycloak and mdm using keycloak password'() {
        when: 'valid call made to login'
        POST('login', adminDetails.keycloakLoginCredentials)

        then:
        verifyResponse(OK, response)
        assert responseBody().emailAddress == adminDetails.emailAddress
    }

    void 'A02 : test logging in as user who exists in both keycloak and mdm using mdm password'() {

        when: 'valid call made to login'
        POST('login', adminDetails.mdmLoginCredentials)

        then:
        verifyResponse(OK, response)
        assert responseBody().emailAddress == adminDetails.emailAddress
    }

    void 'A03 : test logging in as user who exists in both keycloak and mdm using invalid password'() {
        when: 'invalid call made to login'
        POST('login', [
            username: adminDetails.emailAddress,
            password: 'not a valid password'
        ])

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'A04 : test logging in as user who exists in both keycloak and mdm using mdm password with scheme set to keycloak only'() {

        when: 'valid call made to login'
        POST('login?scheme=integratedKeycloak', adminDetails.mdmLoginCredentials)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'K01 : test logging in when user exists in keycloak only using keycloak password'() {

        when: "Keycloak only user login"
        POST('login', keycloakOnlyDetails.keycloakLoginCredentials)

        then: 'keycloak user should be created in the backend'
        verifyResponse(OK, response)
        assert responseBody().id
        assert responseBody().emailAddress == keycloakOnlyDetails.emailAddress
        assert responseBody().firstName == 'Unknown'
        assert responseBody().lastName == 'Unknown'
        assert !responseBody().pending
        assert !responseBody().disabled
        assert responseBody().createdBy == 'keycloakAuthentication@jenkins.cs.ox.ac.uk'

        cleanup:
        deleteUser(responseBody().id as String)
    }

    void 'K02 : test logging in when user exists in keycloak only using mdm password'() {

        when: 'invalid call made to login'
        POST('login', keycloakOnlyDetails.mdmLoginCredentials)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'K03 : test logging in when user exists in keycloak only using keycloak password then check login and logout on created used'() {

        when: "Keycloak only user login"
        POST('login', keycloakOnlyDetails.keycloakLoginCredentials)

        then: 'keycloak user should be created in the backend'
        verifyResponse(OK, response)
        assert responseBody().id
        assert responseBody().emailAddress == keycloakOnlyDetails.emailAddress

        when: 'log out'
        String id = responseBody().id
        GET('logout')

        then:
        verifyResponse(NO_CONTENT, response)

        when: 'log back in using keycloak'
        POST('login', keycloakOnlyDetails.keycloakLoginCredentials)

        then: 'keycloak user should be the same user as before'
        verifyResponse(OK, response)
        assert responseBody().id == id
        assert responseBody().emailAddress == keycloakOnlyDetails.emailAddress

        when: 'log out'
        GET('logout')

        then:
        verifyResponse(NO_CONTENT, response)

        when: 'log in using mdm credentials (no password)'
        POST('login', keycloakOnlyDetails.mdmLoginCredentials)

        then:
        verifyResponse(UNAUTHORIZED, response)

        cleanup:
        deleteUser(id)
    }

    void 'E01 : test logging in as user who exists in mdm only using keycloak password'() {

        when: 'invalid call made to login'
        POST('login', mdmOnlyDetails.keycloakLoginCredentials)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'E02 : test logging in as user who exists in mdm only using mdm password'() {

        when:
        POST('login', mdmOnlyDetails.mdmLoginCredentials)

        then:
        verifyResponse(OK, response)
        assert responseBody().emailAddress == mdmOnlyDetails.emailAddress
    }

    void "test isAuthenticatedSession"() {
        when: "Unlogged in call to check"
        GET('session/isAuthenticated', MAP_ARG, true)

        then: "The response is OK but false"
        verifyResponse(OK, response)
        responseBody().authenticatedSession == false

        when: "logged in"
        POST('login', adminDetails.keycloakLoginCredentials)
        verifyResponse(OK, response)
        GET('session/isAuthenticated', MAP_ARG, true)

        then: "The response is OK and true"
        verifyResponse(OK, response)
        responseBody().authenticatedSession == true
    }

    void "test logout"() {
        given:
        POST('login', adminDetails.keycloakLoginCredentials)
        verifyResponse(OK, response)
        GET('session/isAuthenticated', MAP_ARG, true)
        verifyResponse(OK, response)

        expect:
        responseBody().authenticatedSession == true

        when:
        GET('logout')

        then:
        verifyResponse(NO_CONTENT, response)

        and:
        GET('session/isAuthenticated', MAP_ARG, true)
        verifyResponse(OK, response)
        responseBody().authenticatedSession == false
    }
}
