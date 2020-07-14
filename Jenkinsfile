pipeline {
    agent any

    environment {
        JENKINS = 'true'
    }

    tools {
        jdk 'jdk-12'
    }

    options {
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
        skipStagesAfterUnstable()
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    stages {

        stage('Clean') {
            // Only clean when the last build failed
            when {
                expression {
                    currentBuild.previousBuild?.currentResult == 'FAILURE'
                }
            }
            steps {
                sh "./gradlew clean"
            }
        }

        stage('Info') {
            steps {
                sh './gradlew -v' // Output gradle version for verification checks
                sh './gradlew jvmArgs'
                sh './gradlew sysProps'
            }
        }

        stage('Test cleanup & Compile') {
            steps {
                sh "./gradlew jenkinsClean"
                sh './gradlew compile'
            }
        }


        stage('Functional Test') {

            steps {
                sh "./grailsw -Dgrails.functionalTest=true test-app -integration"
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'build/test-results/functionalTest/*.xml'
                }
            }
        }

        stage('License Header Check') {
            steps {
                sh './gradlew license'
            }
        }
    }

    post {
        always {
            outputTestResults()
            jacoco execPattern: '**/build/jacoco/*.exec'
            archiveArtifacts allowEmptyArchive: true, artifacts: '**/*.log'
            slackNotification()
        }
    }
}