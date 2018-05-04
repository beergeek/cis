require 'spec_helper'
describe 'cis::windows::security_options::domain_controller' do
  let :facts do
    {
      kernel: 'windows',
      os:     { 'family' => 'windows' },
    }
  end

  context 'all defaults' do
		it do
      is_expected.to contain_class('cis::windows::security_options::domain_controller')
    end
		it do
      is_expected.to contain_local_security_policy('Domain controller: Allow server operators to schedule tasks').with(
        'ensure'          => 'present',
        'policy_value'    => 'Disabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Domain controller: LDAP server signing requirements').with(
        'ensure'          => 'present',
        'policy_value'    => 'Require signing',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Domain controller: Refuse machine account password changes').with(
        'ensure'          => 'present',
        'policy_value'    => 'Disabled',
      )
    end
  end
end
