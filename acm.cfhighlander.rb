CfhighlanderTemplate do

  Name 'acm'

  Parameters do
    ComponentParam 'EnvironmentName', 'dev', isGlobal: true
    ComponentParam 'EnvironmentType', 'development', isGlobal: true
    ComponentParam 'DomainName'
    ComponentParam 'CrossAccountDNSZoneIAMRole', ''
  end

  LambdaFunctions 'acm_custom_resources'

end
