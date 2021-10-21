from os import environ

WORKFLOW_DIR = '/opt/aws/**/*.yaml' if not environ.get('WORKFLOW_DIR') else environ.get('WORKFLOW_DIR')
