require 'spec_helper'
describe 'cis::windows::security_options::network_server' do
  let :facts do
    {
      kernel: 'windows',
      os:     { 'family' => 'windows' },
    }
  end

  context 'all defaults' do
		it do
      is_expected.to contain_class('cis::windows::security_options::network_server')
    end
		it do
      is_expected.to contain_local_security_policy('Microsoft network server: Amount of idle time required before suspending session').with(
        'ensure'          => 'present',
        'policy_value'    => '15',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Microsoft network server: Digitally sign communications (always)').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Microsoft network server: Digitally sign communications (if client agrees)').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Microsoft network server: Disconnect clients when logon hours expire').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Microsoft network server: Server SPN target name validation level').with(
        'ensure'          => 'present',
        'policy_value'    => 'Accept if provided by client',
      )
    end
  end

  context 'Is domain controller' do
    let :params do
      {
        is_domain_controller: true
      }
    end

		it do
      is_expected.to_not contain_local_security_policy('Microsoft network server: Server SPN target name validation level')
    end
  end

end
