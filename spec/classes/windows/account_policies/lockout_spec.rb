require 'spec_helper'
describe 'cis::windows::account_policies::lockout' do
  context 'all defaults' do
    let :facts do
      {
        kernel: 'windows',
        os:     { 'family' => 'windows' },
      }
    end

    it do is_expected.to contain_class('cis::windows::account_policies::lockout') end
    it do
      is_expected.to contain_local_security_policy('Account lockout duration').with(
        'ensure'          => 'present',
        'policy_value'    => '15',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Account lockout threshold').with(
        'ensure'          => 'present',
        'policy_value'    => '10',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Reset account lockout counter after').with(
        'ensure'          => 'present',
        'policy_value'    => '15',
      )
    end
  end

  context 'Incorrect values' do
    let :facts do
      {
        kernel: 'windows',
        os:     { 'family' => 'windows' },
      }
    end
    let :params do
      {
        lockout_duration:   20,
        lockout_reset_time: 30,
      }
    end

    it { is_expected.to compile.and_raise_error(/$lockout_duration must be less than or equal to $lockout_reset_time/) }
  end
end
