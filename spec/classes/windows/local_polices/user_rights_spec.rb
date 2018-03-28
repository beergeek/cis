require 'spec_helper'
describe 'cis::windows::local_policies::user_rights' do
  let :facts do
    {
      kernel: 'windows',
      os:     { 'family' => 'windows' },
    }
  end

  context 'all defaults' do
    it do is_expected.to contain_class('cis::windows::local_policies::user_rights') end
    it do
      is_expected.to contain_local_security_policy('Access Credential Manager as a trusted caller').with(
        'ensure'          => 'present',
        'policy_value'    => 'No One',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Access this computer from the network').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators,Authenticated Users',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Act as part of the operating system').with(
        'ensure'          => 'present',
        'policy_value'    => 'No One',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Add workstations to domain').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Adjust memory quotas for a process').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators,LOCAL SERVICE,NETWORK SERVICE',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Allow log on locally').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Allow log on through Remote Desktop Services').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators,Remote Desktop Users',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Back up files and directories').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Change the system time').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators,LOCAL SERVICE',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Change the time zone').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators,LOCAL SERVICE',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Create a pagefile').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Create a token object').with(
        'ensure'          => 'present',
        'policy_value'    => 'No One',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Create global objects').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Create permanent shared objects').with(
        'ensure'          => 'present',
        'policy_value'    => 'No One',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Create symbolic links').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Debug programs').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Deny access to this computer from the network').with(
        'ensure'          => 'present',
        'policy_value'    => 'Guests,Local account,member of Administrators group',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Deny log on as a batch job').with(
        'ensure'          => 'present',
        'policy_value'    => 'Guests',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Deny log on as a service').with(
        'ensure'          => 'present',
        'policy_value'    => 'Guests',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Deny log on locally').with(
        'ensure'          => 'present',
        'policy_value'    => 'Guests',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Deny log on through Remote Desktop Services').with(
        'ensure'          => 'present',
        'policy_value'    => 'Guests,Local account',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Enable computer and user accounts to be trusted for delegation').with(
        'ensure'          => 'present',
        'policy_value'    => 'No One',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Force shutdown from a remote system').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Generate security audits').with(
        'ensure'          => 'present',
        'policy_value'    => 'LOCAL SERVICE,NETWORK SERVICE',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Impersonate a client after authentication').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Increase scheduling priority').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Load and unload device drivers').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Lock pages in memory').with(
        'ensure'          => 'present',
        'policy_value'    => 'No One',
      )
    end
    it do
      is_expected.to_not contain_local_security_policy('Log on as a batch job')
    end
    it do
      is_expected.to contain_local_security_policy('Manage auditing and security log').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Modify an object label').with(
        'ensure'          => 'present',
        'policy_value'    => 'No One',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Modify firmware environment values').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Perform volume maintenance tasks').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Profile single process').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Profile system performance').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators,NT SERVICE\WdiServiceHost',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Replace a process level token').with(
        'ensure'          => 'present',
        'policy_value'    => 'LOCAL SERVICE,NETWORK SERVICE',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Restore files and directories').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Shut down the system').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Synchronize directory service data').with(
        'ensure'          => 'present',
        'policy_value'    => 'No One',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Take ownership of files or other objects').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
  end

  context 'Some different params' do
    let :params do
      {
        profile_sys_perf: ['Administrators','Brett', 'Dylan', 'Jesse'],
        replace_proc_lvl_token: ['LOCAL SERVICE', 'NETWORK SERVICE', 'Sanvy', 'DA', 'Simon'],
        restore_files_dirs: ['Administrators', 'KW', 'Andrew', 'James'],
      }
    end

    it do
      is_expected.to contain_local_security_policy('Profile system performance').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators,Brett,Dylan,Jesse',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Replace a process level token').with(
        'ensure'          => 'present',
        'policy_value'    => 'LOCAL SERVICE,NETWORK SERVICE,Sanvy,DA,Simon',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Restore files and directories').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators,KW,Andrew,James',
      )
    end
  end

  context 'As domain controller' do
    let :params do
      {
        is_domain_controller: true,
      }
    end

    it do
      is_expected.to contain_local_security_policy('Access this computer from the network').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators,Authenticated Users,ENTERPRISE DOMAIN CONTROLLERS',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Add workstations to domain').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Allow log on through Remote Desktop Services').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
    it do
      is_expected.to_not contain_local_security_policy('Log on as a batch job')
    end
    it do
      is_expected.to contain_local_security_policy('Deny access to this computer from the network').with(
        'ensure'          => 'present',
        'policy_value'    => 'Guests,Local account',
      )
    end
    it do
      is_expected.to contain_local_security_policy('Enable computer and user accounts to be trusted for delegation').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
  end

  context 'With Level 2 and as a domain controller' do
    let :params do
      {
        is_domain_controller: true,
        enable_level_2: true
      }
    end

    it do
      is_expected.to contain_local_security_policy('Log on as a batch job').with(
        'ensure'          => 'present',
        'policy_value'    => 'Administrators',
      )
    end
  end
end
