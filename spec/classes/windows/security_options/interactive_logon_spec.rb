require 'spec_helper'
describe 'cis::windows::security_options::interactive_logon' do
  let :facts do
    {
      kernel: 'windows',
      os:     { 'family' => 'windows' },
    }
  end
  let :params do
    {
      logon_message: 'This is the logon message',
      logon_title: 'Logon Title',
    }
  end

  context 'all defaults' do
		it do is_expected.to contain_class('cis::windows::security_options::interactive_logon') end
		it do
      is_expected.to contain_local_security_policy('Interactive logon: Do not display last user name').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Interactive logon: Do not require CTRL+ALT+DEL').with(
        'ensure'          => 'present',
        'policy_value'    => 'Disabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Interactive logon: Machine inactivity limit').with(
        'ensure'          => 'present',
        'policy_value'    => '900',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Interactive logon: Message text for users attempting to log on').with(
        'ensure'          => 'present',
        'policy_value'    => 'This is the logon message',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Interactive logon: Message title for users attempting to log on').with(
        'ensure'          => 'present',
        'policy_value'    => 'Logon Title',
      )
    end
		it do
      is_expected.to_not contain_local_security_policy('Interactive logon: Number of previous logons to cache (in case domain controller is not available)')
    end
		it do
      is_expected.to contain_local_security_policy('Interactive logon: Prompt user to change password before expiration').with(
        'ensure'          => 'present',
        'policy_value'    => '10',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Interactive logon: Require Domain Controller Authentication to unlock workstation').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Interactive logon: Smart card removal behavior').with(
        'ensure'          => 'present',
        'policy_value'    => 'Lock Workstation',
      )
    end
  end

  context 'Enable level 2' do
    let :params do
      {
        logon_message: 'This is the logon message',
        logon_title: 'Logon Title',
        enable_level_2: true,
      }
    end
    it do
      is_expected.to contain_local_security_policy('Interactive logon: Number of previous logons to cache (in case domain controller is not available)').with(
        'ensure'          => 'present',
        'policy_value'    => '4',
      )
    end
  end

  context 'As Domain Controller' do
    let :params do
      {
        logon_message: 'This is the logon message',
        logon_title: 'Logon Title',
        is_domain_controller: true,
      }
    end
		it do
      is_expected.to_not contain_local_security_policy('Interactive logon: Require Domain Controller Authentication to unlock workstation')
    end
  end
end
