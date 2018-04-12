require 'spec_helper'
describe 'cis::windows::security_options::accounts' do
  let :facts do
    {
      kernel: 'windows',
      os:     { 'family' => 'windows' },
    }
  end
  let :params do
    {
      admin_account_name: 'Rob',
      guest_account_name: 'Joe',
    }
  end

  context 'all defaults' do
		it do is_expected.to contain_class('cis::windows::security_options::accounts') end
		it do
      is_expected.to contain_local_security_policy('Accounts: Administrator account status').with(
        'ensure'          => 'present',
        'policy_value'    => 'Disabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Accounts: Block Microsoft accounts').with(
        'ensure'          => 'present',
        'policy_value'    => "Users can't add or log on with Microsoft accounts",
      )
    end
		it do
      is_expected.to contain_local_security_policy('Accounts: Guest account status').with(
        'ensure'          => 'present',
        'policy_value'    => 'Disabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Accounts: Limit local account use of blank passwords to console logon only').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Accounts: Rename administrator account').with(
        'ensure'          => 'present',
        'policy_value'    => 'Rob',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Accounts: Rename guest account').with(
        'ensure'          => 'present',
        'policy_value'    => 'Joe',
      )
    end
  end
end
