node {
    stage('Build') {
        docker.image('debian:testing').inside {
            sh 'sudo apt-get update && sudo apt-get install build-essential && make -C third_party/ && make'
        }
    }
}
