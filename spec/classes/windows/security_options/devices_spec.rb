require 'spec_helper'
describe 'cis::windows::security_options::devices' do
  let :facts do
    {
      kernel: 'windows',
      os:     { 'family' => 'windows' },
    }
  end

  context 'all defaults' do
		it do
      is_expected.to contain_class('cis::windows::security_options::devices')
    end
		it do
      is_expected.to contain_local_security_policy('Devices: Allowed to format and eject removable media').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Devices: Prevent users from installing printer drivers').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
  end
end
