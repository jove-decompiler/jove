node {
    stage('Build') {
        docker.image('debian:testing').inside {
            sh 'make -C third_party/ && make'
        }
    }
}
