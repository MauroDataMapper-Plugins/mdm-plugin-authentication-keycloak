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

import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInternalException
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.security.authentication.AuthenticationSchemeService

import grails.gorm.transactions.Transactional
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import org.springframework.beans.factory.annotation.Value

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

    @Override
    String getName() {
        'keycloak'
    }

    @Override
    String getDisplayName() {
        'Keycloak Authentication'
    }

    @Override
    CatalogueUser authenticateAndObtainUser(String emailAddress, String password) {

        log.debug("Authenticating user ${emailAddress} using Keycloak authentication")
        if (!emailAddress) return null

        HttpClient client = HttpClient.create(baseUrl.toURL())

        HashMap<String, String> data = new HashMap<>()
        data.put("client_id", clientId)
        data.put("client_secret", clientSecret)
        data.put("grant_type", "password")
        data.put("scope", "openid")
        data.put("username", emailAddress)
        data.put("password", password)

        try {
            HttpRequest request = HttpRequest.POST("realms/${realm}/protocol/openid-connect/token", data)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .accept(MediaType.APPLICATION_JSON_TYPE)

            // TODO: Make non-blocking
            HttpResponse<String> response = client.toBlocking().exchange(request)

            CatalogueUser user = catalogueUserService.findByEmailAddress(emailAddress)

            if (user == null) {
                user = catalogueUserService.createNewUser(
                    emailAddress: emailAddress
                )
            }

            user
        }
        catch (HttpClientResponseException e) {
            // 401 returned if credentials invalid
            if (e.getStatus() == HttpStatus.UNAUTHORIZED)
                null
            else
                throw new ApiInternalException(e.getStatus().toString(), e.getMessage(), e)
        }
    }

    @Override
    int getOrder() {
        LOWEST_PRECEDENCE
    }
}
