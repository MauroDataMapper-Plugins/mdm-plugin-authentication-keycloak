# mdm-plugin-authentication-keycloak

| Branch | Build Status |
| ------ | ------------ |
| main | [![Build Status](https://jenkins.cs.ox.ac.uk/buildStatus/icon?job=Mauro+Data+Mapper+Plugins%2Fmdm-plugin-authentication-keycloak%2Fmain)](https://jenkins.cs.ox.ac.uk/blue/organizations/jenkins/Mauro%20Data%20Mapper%20Plugins%2Fmdm-plugin-authentication-keycloak/branches) |
| develop | [![Build Status](https://jenkins.cs.ox.ac.uk/buildStatus/icon?job=Mauro+Data+Mapper+Plugins%2Fmdm-plugin-authentication-keycloak%2Fdevelop)](https://jenkins.cs.ox.ac.uk/blue/organizations/jenkins/Mauro%20Data%20Mapper%20Plugins%2Fmdm-plugin-authentication-keycloak/branches) |

## Requirements

* Java 17 (Temurin)
* Grails 5.1.7+
* Gradle 7.3.3+

## Url Mappings Report

See the following files for the available URLs.

* `mdm-core/README.md`
* `mdm-security/README.md`

## Applying the Plugin

The preferred way of running Mauro Data Mapper is using the [mdm-docker](https://github.com/MauroDataMapper/mdm-docker) deployment. However you can
also run the backend on its own from [mdm-application-build](https://github.com/MauroDataMapper/mdm-application-build).

### mdm-docker

In the `docker-compose.yml` file add:

```yml
mauro-data-mapper:
    build:
        args:
            ADDITIONAL_PLUGINS: "uk.ac.ox.softeng.maurodatamapper.plugins:mdm-plugin-authentication-keycloak:3.1.0"
```

Please note, if adding more than one plugin, this is a semicolon-separated list

### mdm-application-build

In the `build.gradle` file add:

```groovy
grails {
    plugins {
        runtimeOnly 'uk.ac.ox.softeng.maurodatamapper.plugins:mdm-plugin-authentication-keycloak:3.1.0'
    }
}
```

