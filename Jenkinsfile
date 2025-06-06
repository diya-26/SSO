pipeline {
    agent any

    parameters {
        string(name: 'CUSTOMER_SSO_ACCOUNT', description: 'Customer SSO AWS Account ID')
        string(name: 'CUSTOMER_SSO_REGION',  description: 'Customer SSO AWS Region')
        string(name: 'CK_SSO_ACCOUNT',description: 'CK SSO AWS Account ID')
        string(name: 'CK_SSO_REGION',description: 'CK SSO AWS Region')
    }

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
                        python3 application_assignment.py "$CUSTOMER_SSO_ACCOUNT" "$CUSTOMER_SSO_REGION" "$CK_SSO_ACCOUNT" "$CK_SSO_REGION"
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
