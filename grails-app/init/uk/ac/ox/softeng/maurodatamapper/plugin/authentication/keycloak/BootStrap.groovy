/*
 * Copyright 2020 University of Oxford and Health and Social Care Information Centre, also known as NHS Digital
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


import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.utils.SecurityDefinition

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.MessageSource

import static uk.ac.ox.softeng.maurodatamapper.util.GormUtils.checkAndSave

class BootStrap implements SecurityDefinition {

    @Autowired
    MessageSource messageSource

    def init = {servletContext ->

        environments {
            development {
                CatalogueUser.withNewTransaction {

                    createModernSecurityUsers('development', false)
                    checkAndSave(messageSource, editor, reader, authenticated, pending, containerAdmin, author, reviewer)

                    createBasicGroups('development', false)
                    checkAndSave(messageSource, editors, readers)
                }
            }
            test {
                CatalogueUser.withNewTransaction {

                    createModernSecurityUsers('functionalTest', false)
                    checkAndSave(messageSource, editor, reader, authenticated, pending, containerAdmin, author, reviewer)

                    createBasicGroups('functionalTest', false)
                    checkAndSave(messageSource, editors, readers)
                }
            }
        }
    }
    def destroy = {
    }
}
