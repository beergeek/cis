require 'spec_helper'
describe 'cis::windows::security_options::network_client' do
  let :facts do
    {
      kernel: 'windows',
      os:     { 'family' => 'windows' },
    }
  end

  context 'all defaults' do
		it do
      is_expected.to contain_class('cis::windows::security_options::network_client')
    end
		it do
      is_expected.to contain_local_security_policy('Microsoft network client: Digitally sign communications (always)').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Microsoft network client: Digitally sign communications (if server agrees)').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Microsoft network client: Send unencrypted password to third-party SMB servers').with(
        'ensure'          => 'present',
        'policy_value'    => 'Disabled',
      )
    end
  end
end
