node {
    stage('Build') {
        docker.image('debian:testing').inside {
            sh 'cd third_party/ && make build-llvm && cd .. && make'
        }
    }
}
