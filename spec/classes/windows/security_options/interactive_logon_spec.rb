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
      logon_message: 'This is the logon message'
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
#    it do
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
#		it do
#      is_expected.to contain_local_security_policy('').with(
#        'ensure'          => 'present',
#        'policy_value'    => '',
#      )
#    end
  end
end
