@Library('corsha-jenkins-lib@v1.12.1') _

import com.corsha.testing.*

podTemplate(cloud: 'kubernetes-dev', imagePullSecrets: [ 'jenkins-artifactory-pullsecret' ], yaml: builderSetup.specifyBuilderPodTemplate([
    disableLimits: true
])) {    node(POD_LABEL) {
        def scmInfo = null
        def version = null
        boolean isRelease = null
        boolean runE2ETests = true
        boolean secondNotification = true
        env.VERSION = '0.0.0-unknown'

        stage('checkout') {
            container('jnlp') {
                scmInfo = checkout scm
            }
        }

        def buildErr = null
        try {
            String piperContainerID, orchestratorContainerID, generatorContainerID = null
            String corshaDeployDir = null
            stage('setup') {
                container('jnlp') {
                    builderSetup.installJfrog()
                    builderSetup.authenticateGAR()
                    builderSetup.prepGitSSHCreds()

                    corshaDeployDir = builderSetup.downloadCorshaDeploy()
                    //obtain corshactl version
                    version = builderSetup.getVersion()
                    //initialize env variable VERSION
                    env.VERSION = version
                    //set corshactl isRelease
                    isRelease = builderSetup.isRelease()
                    builderSetup.copyK8sConfig()
                    builderSetup.installGCPCreds()
                    builderSetup.installAWSCreds()

                    builderSetup.installDevKey()
                }
            }

            //run common build stages
            builderSetup.commonStages()

            stage('Containerize') {
                container('jnlp') {
                    def permittedVulns = [
                        // For allowlisting, each vulnerability requires a case-by-case discussion.
                        // Please reach out to code owners for consultation.
                    ]

                    sslProxyContainerID = builderSetup.buildContainer('.', 'Dockerfile', permittedVulns)
                    echo "built SSLProxy container with ID: $sslProxyContainerID"
                }
            }

            stage('Publish Containers') {
                container('jnlp') {
                    builderSetup.publishContainer('SSLProxy', sslProxyContainerID, isRelease, version, scmInfo)
                }
            }

        } catch (Exception err) {
            currentBuild.result = 'FAILURE'
            buildErr = err
            println err
        } finally {
            builderSetup.notifyStage('jnlp', this, currentBuild.result, buildErr.toString(), scm, scmInfo)
        }
    }
}
