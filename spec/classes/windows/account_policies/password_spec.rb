require 'spec_helper'
describe 'cis::windows::account_policies::passwords' do
  context 'all defaults' do
    let :facts do
      {
        kernel: 'windows',
        os:     { 'family' => 'windows' },
      }
    end

    it do is_expected.to contain_class('cis::windows::account_policies::passwords') end
    it do
      is_expected.to contain_local_security_policy('Enforce password history').with(
        'ensure'          => 'present',
        'policy_value'    => '24',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Maximum password age').with(
        'ensure'          => 'present',
        'policy_value'    => '60',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Minimum password age').with(
        'ensure'          => 'present',
        'policy_value'    => '1',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Minimum password length').with(
        'ensure'          => 'present',
        'policy_value'    => '14',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Password must meet complexity requirements').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Store passwords using reversible encryption').with(
        'ensure'          => 'present',
        'policy_value'    => 'Disabled',
      )
    end
  end
end
