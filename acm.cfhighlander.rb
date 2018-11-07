CfhighlanderTemplate do

  Name 'acm'

  Parameters do
    ComponentParam 'EnvironmentName', 'dev', isGlobal: true
    ComponentParam 'EnvironmentType', 'development', isGlobal: true
    ComponentParam 'DomainName'
  end

  LambdaFunctions 'acm_custom_resources'

end
