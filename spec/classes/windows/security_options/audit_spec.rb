require 'spec_helper'
describe 'cis::windows::security_options::audit' do
  let :facts do
    {
      kernel: 'windows',
      os:     { 'family' => 'windows' },
    }
  end

  context 'all defaults' do
		it do is_expected.to contain_class('cis::windows::security_options::audit') end
		it do
      is_expected.to contain_local_security_policy('Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings').with(
        'ensure'          => 'present',
        'policy_value'    => 'Enabled',
      )
    end
		it do
      is_expected.to contain_local_security_policy('Audit: Shut down system immediately if unable to log security audits').with(
        'ensure'          => 'present',
        'policy_value'    => 'Disabled',
      )
    end
  end
end
