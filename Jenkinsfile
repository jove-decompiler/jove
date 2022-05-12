node {
    def imageName = "jove_ci:4"

    timestamps {
        gitlabBuilds(builds: ["Checkout", "Build", "TestSetup", "Test"]) {
            stage('Checkout') {
                gitlabCommitStatus("Checkout") {
                        checkout scm
                    }
                }

            docker.withRegistry("https://apps.aarno-labs.com", "aarno_apps") {
                docker.image(imageName).inside {
                    stage('Build') {
                        gitlabCommitStatus("Build") {
                            sh "make distclean && make build-llvm && make -j`nproc`"
                        }
                    }

                    stage('Deploy') {
                        gitlabCommitStatus("Deploy") {
                            sh "make package"

                            archiveArtifacts '*.tar.xz'
                        }
                    }
                }
            }
        }
    }
}
