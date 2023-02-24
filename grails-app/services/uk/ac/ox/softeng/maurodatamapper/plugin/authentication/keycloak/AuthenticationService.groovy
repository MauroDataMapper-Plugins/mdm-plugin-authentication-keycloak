/*
 * Copyright 2020-2023 University of Oxford and NHS England
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

import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiBadRequestException
import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInternalException
import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInvalidModelException
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.security.authentication.AuthenticationSchemeService

import grails.gorm.transactions.Transactional
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import org.springframework.beans.factory.annotation.Value

/**
 * Attempt to get access token
 * Authenticate using https://oauth.net/2/grant-types/password/
 * Url endpoint and body content https://www.keycloak.org/docs/latest/server_admin/#troubleshooting-2
 * https://stackoverflow.com/questions/48220504/login-to-keycloak-using-api
 * <pre>
 * You are effectively asking your users to trust that Application1 will manage their keycloak credentials securely. This is not recommended because
 *
 * better security is achieved if the user is redirected to keycloak to enter their credentials. In an ideal world no client application should be
 * handling or have access to user credentials. It defeats the purpose of single sign in where a user should only need to enter their credentials for
 * the first application they need to access (provided their session has not expired) But if you control and can trust Application1 and need to do
 * this
 * due to legacy or other reasons then you can enable the Resource Owner Credentials Flow called "Direct Access" on the Keycloak Client Definition,
 * and then POST the user's credentials as a form-urlencoded data type to
 *
 * https://<keycloak-url>/auth/realms/<realm>/protocol/openid-connect/token

 * The paramaters will be

 * grant_type=password
 * client_id=<Application1's client id>
 * client_secret=<the client secret>
 * username=<the username>
 * password=<the password>
 * scope=<space delimited list of scope requests>
 * The response will be a valid JWT object or a 4xx error if the credentials are invalid.
 * </pre>
 */
@Transactional
class AuthenticationService implements AuthenticationSchemeService {

    CatalogueUserService catalogueUserService

    @Value('${keycloak.baseUrl}')
    String baseUrl

    @Value('${keycloak.realm}')
    String realm

    @Value('${keycloak.clientId}')
    String clientId

    @Value('${keycloak.clientSecret}')
    String clientSecret

    @Value('${keycloak.protocol}')
    String protocol

    @Value('${keycloak.scope}')
    String scope

    @Value('${keycloak.grantType}')
    String grantType

    @Override
    String getName() {
        'integratedKeycloak'
    }

    @Override
    String getDisplayName() {
        'Integrated Keycloak Authentication'
    }

    @Override
    CatalogueUser authenticateAndObtainUser(Map<String, Object> authenticationInformation) {
        if (!authenticationInformation.username) return null

        log.debug("Authenticating user ${authenticationInformation.username} using ${displayName}")

        try {
            HttpClient
                .create(baseUrl.toURL())
                .toBlocking()
                .exchange(
                    HttpRequest.POST("realms/${realm}/protocol/${protocol}/token", [
                        'client_id'    : clientId,
                        'client_secret': clientSecret,
                        'grant_type'   : grantType,
                        'scope'        : scope,
                        'username'     : authenticationInformation.username,
                        'password'     : authenticationInformation.password,
                    ])
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                        .accept(MediaType.APPLICATION_JSON_TYPE)
                )
        }
        catch (HttpClientResponseException e) {
            // 401 returned if credentials invalid
            switch (e.status) {
                case HttpStatus.UNAUTHORIZED:
                    return null
                case HttpStatus.BAD_REQUEST:
                    throw new ApiBadRequestException('KAS01', 'Could not authenticate against keycloak server due to a bad request')
                default:
                    throw new ApiInternalException('KAS02', "Could not authenticate against keycloak server: ${e.getStatus()} ${e.getMessage()}", e)
            }
        }

        CatalogueUser user = catalogueUserService.findByEmailAddress(authenticationInformation.username)

        if (!user) {
            user = catalogueUserService.createNewUser(emailAddress: authenticationInformation.username, password: null,
                                                      createdBy: "keycloakAuthentication@${baseUrl.toURL().host}",
                                                      pending: false, firstName: 'Unknown', lastName: 'Unknown',
                                                      creationMethod: 'Keycloak-Integrated-Security')
            if (!user.validate()) throw new ApiInvalidModelException('KAS03', 'Invalid user creation', user.errors)
            user.save flush: true, validate: false
            user.addCreatedEdit(user)
        }

        user
    }

    @Override
    int getOrder() {
        0
    }
}
