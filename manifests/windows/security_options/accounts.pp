# A class to manage CIS Standard 2.3.1 for Windows
#
# @param accounts_guest_account_status
# @param 
#
class cis::windows::security_options::accounts (
  String $admin_account_name,
  String $guest_account_name,
  Cis::Enabled_disabled $accounts_admin_account_status      = 'Disabled',
  Cis::Block_accounts $block_ms_accounts                    = "Users can't add or log on with Microsoft accounts",
  Cis::Enabled_disabled $accounts_guest_account_status      = 'Disabled',
  Cis::Enabled_disabled $blank_passords_at_console          = 'Enabled',
  Cis::Enabled_disabled $override_audit_policy_cat_settings = 'Enabled',
  Cis::Enabled_disabled $shutdown_failed_log_sec_audits     = 'Disabled',
) {

  if $::os['family'] != 'windows' {
    fail("This class is only for Windows, not for ${::os['family']}")
  }

  # CIS 2.3.1.1
  if $accounts_admin_account_status != false {
    local_security_policy { 'Accounts: Administrator account status':
      ensure       => present,
      policy_value => $accounts_admin_account_status,
    }
  }

  # CIS 2.3.1.2
  if $block_ms_accounts != false {
    local_security_policy { 'Accounts: Block Microsoft accounts':
      ensure       => present,
      policy_value => $block_ms_accounts,
    }
  }

  # CIS 2.3.1.3
  if $accounts_guest_account_status != false {
    local_security_policy { 'Accounts: Guest account status':
      ensure       => present,
      policy_value => $accounts_guest_account_status,
    }
  }

  # CIS 2.3.1.4
  if $blank_passords_at_console != false {
    local_security_policy { 'Accounts: Limit local account use of blank passwords to console logon only':
      ensure       => present,
      policy_value => $blank_passords_at_console,
    }
  }

  # CIS 2.3.1.5
  local_security_policy { 'Accounts: Rename administrator account':
    ensure       => present,
    policy_value => $admin_account_name,
  }

  # CIS 2.3.1.6
  local_security_policy { 'Accounts: Rename guest account':
    ensure       => present,
    policy_value => $guest_account_name,
  }
}
