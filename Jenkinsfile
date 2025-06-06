pipeline{
    agent any

    stages{
        stage('Checkout'){
            steps{
                checkout scm
            }
        }
        stage('Run Script'){
            steps{
                sh '''
                python3 -m venv venv
                source venv/bin/activate
                pip install --upgrade pip
                pip install -r requirements.txt
                '''
            }

        }

    }
    post{
        success{
            echo 'Success'
        }
        failure{
            echo 'Failed'
        }
    }

}