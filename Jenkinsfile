node {
    def imageName = "jove_ci:2"

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
                            sh "make -C third_party build-llvm && make -j`nproc`"
                        }
                    }
                }
            }
            stage('Deploy') {
                    gitlabCommitStatus("Deploy") {
                            archiveArtifacts 'bin/x86_64/*'
                            archiveArtifacts 'bin/i386/*'
                            archiveArtifacts 'bin/mips32/*'
                            archiveArtifacts 'bin/mips64/*'
                            archiveArtifacts 'bin/aarch64/*'
                    }

                    def output = "$jove.x86_64.multiarch.tar.xz"
                    echo "Compressing installation folder to ${output}"
                    sh "/bin/bash -c 'tar cf - ${installedFolder} | xz -T 0 > ../${output}'"
                    archiveArtifacts "${output}"
                    sh "rm ${output}"
                }
            }
        }
    }
}
