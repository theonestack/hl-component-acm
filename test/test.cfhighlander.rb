CfhighlanderTemplate do

  Description "SS Unify Cloud MDH -Test (#{component_name}@#{component_version})"
  ComponentDistribution 's3://source.ap-southeast-2.tools.ssunify.net/cloudformation/test'

  Component template: 'acm@cross_account_dns.snapshot', name: 'acm' do
    parameter name: 'DomainName', value: FnSub("${EnvironmentName}.ssunify.net")
    parameter name: 'CrossAccountDNSZoneIAMRole', value: 'arn:aws:iam::520057317158:role/opsdns'
  end

  Component template: 'acm@cross_account_dns.snapshot', name: 'acmlocal' do
    parameter name: 'DomainName', value: FnSub("${EnvironmentName}.ssunify-mdh-dev.ssunify.net")
  end


end