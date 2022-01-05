node {
    stage('Build') {
        docker.image('debian:testing').inside {
            sh 'ls && cd third_party/ && make build-llvm && cd .. && make'
        }
    }
}
