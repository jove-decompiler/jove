properties([
    gitLabConnection('Gitlab-LLVM'),
    pipelineTriggers([
        [
            $class: 'GitLabPushTrigger',
            triggerOnPush: true,
            triggerOnMergeRequest: false,
            triggerOpenMergeRequestOnPush: "never",
            triggerOnNoteRequest: true,
            noteRegex: "Jenkins try again plzz",
            skipWorkInProgressMergeRequest: false,
            secretToken: project_token,
            ciSkip: false,
            setBuildDescription: true,
            addNoteOnMergeRequest: true,
            addCiMessage: true,
            addVoteOnMergeRequest: true,
            acceptMergeRequestOnSuccess: false,
            branchFilterType: "NameBasedFilter",
            includeBranchesSpec: "",
            excludeBranchesSpec: "",
        ]
    ])
])

node {
    def codeDir = "code"
    def releaseDir = "release"
    def debugDir = "debug"

    def imageName = 'debian:testing'

    timestamps {
        gitlabBuilds(builds: ["Checkout", "Build", "TestSetup", "Test"]) {
            stage('Checkout') {
                gitlabCommitStatus("Checkout") {
                      checkout scm
                }
            }

            docker.image(imageName).inside {
                stage('Build') {
                    gitlabCommitStatus("Build") {
                        sh "cd third_party/ && " +
                             "ulimit -s unlimited && " +
                              "make build-llvm && " +
                              "cd .. && " +
                            "make"
                    }
                }
            }
        }
    }
}
