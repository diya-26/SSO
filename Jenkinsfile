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
                sh '''
                    pip install --upgrade pip
                    pip install -r requirements.txt
                    python3 assign_sso_roles.py
                '''
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
