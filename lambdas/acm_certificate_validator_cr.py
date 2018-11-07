import time
from aws_acm_cert_validator.logic import AwsAcmCertValidatorLogic

import boto3
import json
import os
import sys
import traceback

MAX_WAIT_TIME = int(os.environ.get('MAX_WAIT_TIME', '1800'))

sys.path.append(f"{os.environ['LAMBDA_TASK_ROOT']}/lib")
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

import cr_response


def handler(event, context):
    print(f"Received event:{json.dumps(event)}")
    domain_name = event['ResourceProperties']['DomainName']
    request_type = event['RequestType']
    if 'AwsRegion' in event['ResourceProperties']:
        os.environ['ACM_REGION'] = event['ResourceProperties']['AwsRegion']
    else:
        os.environ['ACM_REGION'] = os.environ['AWS_REGION']

    try:
        if request_type == 'Create':
            # create and validate cert
            issue_validate_cert_respond(domain_name, event, context)
            return

            # physical id should depend on domain name

        if request_type == 'Update':
            # check if domain name is the same
            existing_domain_name = event['OldResourceProperties']['DomainName']

            if existing_domain_name != domain_name:
                # issue new certificate with new physical id
                issue_validate_cert_respond(domain_name, event, context)
                return
            else:
                # no changes just respond with success
                r = cr_response.CustomResourceResponse(event)
                r.respond({'CertificateArn': event['PhysicalResourceId']})
                return

        if request_type == 'Delete':
            delete_validate_cert(domain_name, event, context)
            return
    except Exception as ex:
        print("Failed CCR Provisioning. Payload:\n" + str(event))
        print(str(ex))
        traceback.print_exc(file=sys.stdout)
        # if there is fallback ARN provided, respond with fallback arn
        if 'FallbackCertificateArn' in event['ResourceProperties']:
            r = cr_response.CustomResourceResponse(event)
            event['PhysicalResourceId'] = event['ResourceProperties']['FallbackCertificateArn']
            r.respond({'CertificateArn': event['ResourceProperties']['FallbackCertificateArn']})
        else:
            r = cr_response.CustomResourceResponse(event)
            r.respond_error(str(ex))

        return

def delete_validate_cert(domain_name, event, context):
    logic = AwsAcmCertValidatorLogic()
    cert_arn = event['PhysicalResourceId']
    if cert_arn.startswith('arn:aws'):
        acm = boto3.client('acm', region_name=os.environ['ACM_REGION'])
        cert_info = acm.describe_certificate(CertificateArn=cert_arn)
        validation_options = cert_info['Certificate']['DomainValidationOptions'][0]
        dns_validation_record = validation_options['ResourceRecord']
        acm.delete_certificate(CertificateArn=cert_arn)
        logic.remove_validation_record(domain_name, dns_validation_record)
    r = cr_response.CustomResourceResponse(event)
    r.respond({'CertificateArn': event['PhysicalResourceId']})

def issue_validate_cert_respond(domain_name, event, context):
    logic = AwsAcmCertValidatorLogic()

    if 'WaitOnly' in event and event['WaitOnly']:
        acm_certificate_arn = event['PhysicalResourceId']
        validation_record = event['ValidationRecord']
    else:
        acm_certificate_arn = logic.request(domain_name=domain_name, event=event)
        validation_record = logic.validate(cert_arn=acm_certificate_arn)

    remaining_lambda_time = (context.get_remaining_time_in_millis() / 1000) - 20
    print(f"Remaining wait secs:{remaining_lambda_time}")
    if 'StartWait' not in event:
        start_wait = time.time()
    else:
        start_wait = int(event['StartWait'])

    result = logic.wait_cert_validated(
        cert_arn=acm_certificate_arn,
        wait_interval_secs=5,
        max_wait_secs=remaining_lambda_time,
        return_empty_on_timeout=True
    )
    if result is None:
        lambda_client = boto3.client('lambda')
        function_name = os.environ['AWS_LAMBDA_FUNCTION_NAME']
        event['PhysicalResourceId'] = acm_certificate_arn
        event['WaitOnly'] = True
        event['ValidationRecord'] = validation_record
        if 'StartWait' not in event:
            event['StartWait'] = start_wait
        if 'WaitIteration' not in event:
            event['WaitIteration'] = 2
        else:
            event['WaitIteration'] += 1

        # if total wait time elapsed raise exception
        if int(time.time()) - int(event['StartWait']) > MAX_WAIT_TIME:
            raise Exception(f"Total wait time of {MAX_WAIT_TIME} elapsed")

        lambda_client.invoke(
            FunctionName=function_name,
            Payload=json.dumps(event).encode('utf-8'),
            InvocationType='Event'
        )
        return

    # remove dns record
    try:
        if 'Cleanup' in event['ResourceProperties'] and event['ResourceProperties']['Cleanup'] == 'true':
            logic.remove_validation_record(domain_name, validation_record)
    except:
        print(f"Faild to remove validation record, continuing... ")
    # respond
    r = cr_response.CustomResourceResponse(event)
    event['PhysicalResourceId'] = acm_certificate_arn
    r.respond({'CertificateArn': acm_certificate_arn})