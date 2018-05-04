require 'spec_helper'
describe 'cis::windows::security_options::network_access' do
  let :facts do
    {
      kernel: 'windows',
      os:     { 'family' => 'windows' },
    }
  end

  context 'all defaults' do
		it do
      is_expected.to contain_class('cis::windows::security_options::network_access')
    end
		it do
      is_expected.to contain_local_security_policy('Network access: Allow anonymous SID/Name translation').with(
        'ensure'          => 'present',
        'policy_value'    => 'Disabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Network access: Do not allow anonymous enumeration of SAM accounts').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Network access: Do not allow anonymous enumeration of SAM accounts and shares').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Network access: Do not allow anonymous enumeration of SAM accounts and shares').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Network access: Do not allow storage of passwords and credentials for network authentication').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Network access: Let Everyone permissions apply to anonymous users').with(
        'ensure'          => 'present',
        'policy_value'    => 'Disabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Network access: Named Pipes that can be accessed anonymously').with(
        'ensure'          => 'present',
        'policy_value'    => ['None'],
      )
    end
#
#		it do
#      is_expected.to contain_local_security_policy('').with(
#        'ensure'          => 'present',
#        'policy_value'    => '',
#      )
#    end
#		it do
#      is_expected.to contain_local_security_policy('').with(
#        'ensure'          => 'present',
#        'policy_value'    => '',
#      )
#    end
#		it do
#      is_expected.to contain_local_security_policy('').with(
#        'ensure'          => 'present',
#        'policy_value'    => '',
#      )
#    end
  end

  context 'as domain controller' do
    let :params do
      {
        is_domain_controller: true
      }
    end

    it do
      is_expected.to_not contain_local_security_policy('Network access: Do not allow anonymous enumeration of SAM accounts')
    end
    it do
      is_expected.to_not contain_local_security_policy('Network access: Do not allow anonymous enumeration of SAM accounts and shares')
    end
    it do
      is_expected.to contain_local_security_policy('Network access: Named Pipes that can be accessed anonymously').with(
        'ensure'        => 'present',
        'policy_value'  => %w[Netlogon samr lsarpc],
      )
    end
  end
end
