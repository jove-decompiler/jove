node {
    stage('Build') {
        docker.image('debian:testing').inside {
            sh 'apt update && apt install build-essential && make -C third_party/ && make'
        }
    }
}
