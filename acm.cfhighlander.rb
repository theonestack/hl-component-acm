CfhighlanderTemplate do

  Parameters do
    ComponentParam 'EnvironmentName', 'dev', isGlobal: true
    ComponentParam 'EnvironmentType', 'development', isGlobal: true
    ComponentParam 'DomainName'
    ComponentParam 'AwsRegion', ''
  end

  LambdaFunctions 'acm_custom_resources'

end
