pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Run Script') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'aws-credentials', 
                                                 usernameVariable: 'AWS_ACCESS_KEY_ID', 
                                                 passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {
                    sh '''
                        pip install -r requirements.txt
                        python3 assign_sso_roles.py
                    '''
                }
            }
        }
    }

    post {
        success {
            echo 'Success'
        }
        failure {
            echo 'Failed'
        }
    }
}
