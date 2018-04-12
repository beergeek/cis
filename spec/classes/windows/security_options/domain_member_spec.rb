require 'spec_helper'
describe 'cis::windows::security_options::domain_member' do
  let :facts do
    {
      kernel: 'windows',
      os:     { 'family' => 'windows' },
    }
  end

  context 'all defaults' do
		it do is_expected.to contain_class('cis::windows::security_options::domain_member') end
		it do
      is_expected.to contain_local_security_policy('Domain member: Digitally encrypt or sign secure channel data (always)').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Domain member: Digitally encrypt secure channel data (when possible)').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Domain member: Digitally sign secure channel data (when possible)').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Domain member: Disable machine account password changes').with(
        'ensure'          => 'present',
        'policy_value'    => 'Disabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Domain member: Maximum machine account password age').with(
        'ensure'          => 'present',
        'policy_value'    => '30',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Domain member: Require strong (Windows 2000 or later) session key').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
  end
end
