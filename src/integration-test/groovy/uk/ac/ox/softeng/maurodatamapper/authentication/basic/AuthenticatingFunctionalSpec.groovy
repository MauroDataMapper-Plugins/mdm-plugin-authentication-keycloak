/*
 * Copyright 2020 University of Oxford
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
package uk.ac.ox.softeng.maurodatamapper.authentication.keycloak

import uk.ac.ox.softeng.maurodatamapper.core.bootstrap.StandardEmailAddress
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.basic.UnloggedUser
import uk.ac.ox.softeng.maurodatamapper.security.utils.SecurityDefinition
import uk.ac.ox.softeng.maurodatamapper.security.utils.SecurityUtils
import uk.ac.ox.softeng.maurodatamapper.test.functional.BaseFunctionalSpec

import grails.core.GrailsApplication
import grails.gorm.transactions.Transactional
import grails.testing.mixin.integration.Integration
import grails.testing.spock.OnceBefore
import groovy.transform.TupleConstructor
import groovy.util.logging.Slf4j
import org.keycloak.admin.client.CreatedResponseUtil
import org.keycloak.admin.client.KeycloakBuilder
import org.keycloak.admin.client.resource.UsersResource
import org.keycloak.representations.idm.CredentialRepresentation
import org.keycloak.representations.idm.UserRepresentation
import spock.lang.Shared

import javax.ws.rs.core.Response

import static io.micronaut.http.HttpStatus.NO_CONTENT
import static io.micronaut.http.HttpStatus.OK
import static io.micronaut.http.HttpStatus.UNAUTHORIZED

/**
 * @see uk.ac.ox.softeng.maurodatamapper.security.authentication.AuthenticatingController* Controller: authentication
 *  | *    | /api/authentication/logout                 | Action: logout         |
 *  | POST | /api/authentication/login                  | Action: login          |
 *  | GET  | /api/authentication/isAuthenticatedSession | Action: isAuthenticatedSession |
 */
@Integration
@Slf4j
class AuthenticatingFunctionalSpec extends BaseFunctionalSpec implements SecurityDefinition {

    @Override
    String getResourcePath() {
        'authentication'
    }

    @TupleConstructor
    class KeycloakDetails {
        String id
        String username
        String password
    }

    GrailsApplication grailsApplication

    String getServerUrl() {
        grailsApplication.config.keycloak.baseUrl
    }

    String getRealm() {
        grailsApplication.config.keycloak.realm
    }

    String getAdminRealm() {
        grailsApplication.config.keycloak.admin.realm
    }

    String getAdminUsername() {
        grailsApplication.config.keycloak.admin.username
    }

    String getAdminPassword() {
        grailsApplication.config.keycloak.admin.password
    }

    String getAdminClientId() {
        grailsApplication.config.keycloak.admin.clientId
    }

    String getAdminClientSecret() {
        grailsApplication.config.keycloak.admin.clientSecret
    }

    @Shared
    UsersResource usersResource

    @Shared
    KeycloakDetails adminDetails

    @OnceBefore
    @Transactional
    def checkAndSetupData() {
        createModernSecurityUsers('functionalTest')
        checkAndSave(admin)
        checkAndSave(editor)
        checkAndSave(pending)
        checkAndSave(reader)
        checkAndSave(authenticated)

        usersResource = KeycloakBuilder.builder()
            .serverUrl(getServerUrl())
            .realm(getAdminRealm())
            .username(getAdminUsername())
            .password(getAdminPassword())
            .clientId(getAdminClientId())
            .clientSecret(getAdminClientSecret())
            .build()
            .realm(getRealm())
            .users()

        adminDetails = createKeycloakUser(admin.emailAddress)
    }

    KeycloakDetails createKeycloakUser(String username) {
        if (usersResource.search(username).any()) {
            throw new IllegalArgumentException("Username \"${username}\" already exists")
        }

        UserRepresentation user = new UserRepresentation()
        user.setUsername(username)
        user.setEnabled(true)

        Response createUserResponse = usersResource.create(user)
        String userId = CreatedResponseUtil.getCreatedId(createUserResponse)

        String password = SecurityUtils.generateRandomPassword()
        CredentialRepresentation credentials = new CredentialRepresentation()
        credentials.setTemporary(false)
        credentials.setType(CredentialRepresentation.PASSWORD)
        credentials.setValue(password)

        usersResource.get(userId).resetPassword(credentials)

        new KeycloakDetails(userId, username, password)
    }

    @Transactional
    def cleanupSpec() {
        CatalogueUser.list().findAll {
            !(it.emailAddress in [UnloggedUser.UNLOGGED_EMAIL_ADDRESS, StandardEmailAddress.ADMIN])
        }.each {it.delete(flush: true)}

        usersResource.delete(adminDetails.id)
    }

    void 'test logging in'() {
        when: 'invalid call made to login'
        POST('login', [
            username: adminDetails.username,
            password: 'not a valid password'
        ])

        then:
        verifyResponse(UNAUTHORIZED, response)

        when: 'valid call made to login'
        POST('login', [
            username: adminDetails.username,
            password: adminDetails.password
        ], STRING_ARG)

        then:
        verifyJsonResponse(OK, '''{
  "id": "${json-unit.matches:id}",
  "emailAddress": "admin@maurodatamapper.com",
  "firstName": "Admin",
  "lastName": "User",
  "pending": false,
  "disabled": false,
  "createdBy": "admin@maurodatamapper.com"
}''')

        when:
        GET('session/isAuthenticated', MAP_ARG, true)

        then:
        verifyResponse(OK, response)
        response.body().authenticatedSession == true
    }

    void 'test logging in when no CatalogueUser'() {
        String email = "keycloak-only@test.com"
        KeycloakDetails keycloakOnlyUser = createKeycloakUser(email)

        when: "Keycloak only user login"
        POST('login', [
            username: keycloakOnlyUser.username,
            password: keycloakOnlyUser.password
        ], STRING_ARG)

        then:
        verifyJsonResponse(OK, '''{
  "id": null,
  "emailAddress": "keycloak-only@test.com",
  "firstName": null,
  "lastName": null,
  "pending": null,
  "disabled": null,
  "createdBy": "keycloak-only@test.com"
}''')

        cleanup: "delete keycloak only user"
        usersResource.delete(keycloakOnlyUser.id)
    }

    void "test isAuthenticatedSession"() {
        when: "Unlogged in call to check"
        GET('session/isAuthenticated', MAP_ARG, true)

        then: "The response is OK but false"
        verifyResponse(OK, response)
        response.body().authenticatedSession == false

        when: "logged in"
        POST('login', [
            username: adminDetails.username,
            password: adminDetails.password
        ])
        verifyResponse(OK, response)
        GET('session/isAuthenticated', MAP_ARG, true)

        then: "The response is OK and true"
        verifyResponse(OK, response)
        response.body().authenticatedSession == true
    }

    void "test logout"() {
        given:
        POST('login', [
            username: adminDetails.username,
            password: adminDetails.password
        ])
        verifyResponse(OK, response)
        GET('session/isAuthenticated', MAP_ARG, true)
        verifyResponse(OK, response)

        expect:
        response.body().authenticatedSession == true

        when:
        GET('logout')

        then:
        verifyResponse(NO_CONTENT, response)

        and:
        GET('session/isAuthenticated', MAP_ARG, true)
        verifyResponse(OK, response)
        response.body().authenticatedSession == false
    }
}
