require 'yaml'

describe 'compiled component acm' do
  
  context 'cftest' do
    it 'compiles test' do
      expect(system("cfhighlander cftest #{@validate} --tests tests/default.test.yaml")).to be_truthy
    end      
  end
  
  let(:template) { YAML.load_file("#{File.dirname(__FILE__)}/../out/tests/default/acm.compiled.yaml") }
  
  context "Resource" do

    
    context "ACMCertificate" do
      let(:resource) { template["Resources"]["ACMCertificate"] }

      it "is of type Custom::CertificateValidator" do
          expect(resource["Type"]).to eq("Custom::CertificateValidator")
      end
      
      it "to have property ServiceToken" do
          expect(resource["Properties"]["ServiceToken"]).to eq({"Fn::GetAtt"=>["CertificateValidatorCR", "Arn"]})
      end
      
      it "to have property AwsRegion" do
          expect(resource["Properties"]["AwsRegion"]).to eq({"Fn::If"=>["HasRegion", {"Ref"=>"AwsRegion"}, {"Ref"=>"AWS::Region"}]})
      end
      
      it "to have property DomainName" do
          expect(resource["Properties"]["DomainName"]).to eq({"Ref"=>"DomainName"})
      end
      
      it "to have property AlternativeNames" do
          expect(resource["Properties"]["AlternativeNames"]).to eq("")
      end
      
      it "to have property Tags" do
          expect(resource["Properties"]["Tags"]).to eq([{"Key"=>"Name", "Value"=>{"Ref"=>"AWS::StackName"}}, {"Key"=>"Environment", "Value"=>{"Ref"=>"EnvironmentName"}}, {"Key"=>"EnvironmentType", "Value"=>{"Ref"=>"EnvironmentType"}}])
      end
      
    end
    
    context "LambdaRoleCertificateValidatorResource" do
      let(:resource) { template["Resources"]["LambdaRoleCertificateValidatorResource"] }

      it "is of type AWS::IAM::Role" do
          expect(resource["Type"]).to eq("AWS::IAM::Role")
      end
      
      it "to have property AssumeRolePolicyDocument" do
          expect(resource["Properties"]["AssumeRolePolicyDocument"]).to eq({"Version"=>"2012-10-17", "Statement"=>[{"Effect"=>"Allow", "Principal"=>{"Service"=>"lambda.amazonaws.com"}, "Action"=>"sts:AssumeRole"}]})
      end
      
      it "to have property Path" do
          expect(resource["Properties"]["Path"]).to eq("/")
      end
      
      it "to have property Policies" do
          expect(resource["Properties"]["Policies"]).to eq([{"PolicyName"=>"cloudwatch-logs", "PolicyDocument"=>{"Statement"=>[{"Effect"=>"Allow", "Action"=>["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams", "logs:DescribeLogGroups"], "Resource"=>["arn:aws:logs:*:*:*"]}]}}, {"PolicyName"=>"acm", "PolicyDocument"=>{"Statement"=>[{"Effect"=>"Allow", "Action"=>["acm:*", "route53:*"], "Resource"=>"*"}]}}, {"PolicyName"=>"lambda", "PolicyDocument"=>{"Statement"=>[{"Effect"=>"Allow", "Action"=>["lambda:InvokeFunction"], "Resource"=>"*"}]}}])
      end
      
    end
    
    context "CertificateValidatorCR" do
      let(:resource) { template["Resources"]["CertificateValidatorCR"] }

      it "is of type AWS::Lambda::Function" do
          expect(resource["Type"]).to eq("AWS::Lambda::Function")
      end
      
      it "to have property Code" do
          expect(resource["Properties"]["Code"]["S3Bucket"]).to eq("")
          expect(resource["Properties"]["Code"]["S3Key"]).to start_with("/latest/CertificateValidatorCR.acm.latest")
      end
      
      it "to have property Environment" do
          expect(resource["Properties"]["Environment"]).to eq({"Variables"=>{"ENVIRONMENT_NAME"=>{"Ref"=>"EnvironmentName"}}})
      end
      
      it "to have property Handler" do
          expect(resource["Properties"]["Handler"]).to eq("acm_certificate_validator_cr.handler")
      end
      
      it "to have property MemorySize" do
          expect(resource["Properties"]["MemorySize"]).to eq(128)
      end
      
      it "to have property Role" do
          expect(resource["Properties"]["Role"]).to eq({"Fn::GetAtt"=>["LambdaRoleCertificateValidatorResource", "Arn"]})
      end
      
      it "to have property Runtime" do
          expect(resource["Properties"]["Runtime"]).to eq("python3.7")
      end
      
      it "to have property Timeout" do
          expect(resource["Properties"]["Timeout"]).to eq(600)
      end
      
    end
    
  end

end