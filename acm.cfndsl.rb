CloudFormation do

  Condition("HasRegion", FnNot(FnEquals(Ref('AwsRegion'), '')))

  cert_tags = []
  cert_tags << { Key: "Name", Value: Ref('AWS::StackName') }
  cert_tags << { Key: "Environment", Value: Ref("EnvironmentName") }
  cert_tags << { Key: "EnvironmentType", Value: Ref("EnvironmentType") }

  tags = external_parameters.fetch(:tags, {})
  tags.each do |key, value|
    cert_tags << { Key: key, Value: value }
  end

  alternative_names = external_parameters.fetch(:alternative_names, '')
  Resource("ACMCertificate") do
    Type 'Custom::CertificateValidator'
    Property 'ServiceToken',FnGetAtt('CertificateValidatorCR','Arn')
    Property 'AwsRegion', FnIf('HasRegion', Ref('AwsRegion'), Ref('AWS::Region'))
    Property 'DomainName', Ref('DomainName')
    Property 'AlternativeNames', alternative_names
    Property 'Tags', cert_tags
  end

  Output("CertificateArn") {
    Value(Ref('ACMCertificate'))
    Export(FnSub("${EnvironmentName}-#{external_parameters[:component_name]}-cert-arn"))
  }

end
