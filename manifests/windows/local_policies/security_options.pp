# ccounts: Rename administrator account
#
# @param accounts_guest_account_status
# @param 
#
class cis::windows::local_policies::accounts (
  String $admin_account_name,
  String $guest_account_name,
  Cis::Enabled_disabled $accounts_guest_account_status = 'Disabled',
  Cis::Enabled_disabled $blank_passords_at_console     = 'Enabled',
  Cis::Enabled_disabled $override_audit_policy_cat_settings = 'Enabled',
  Cis::Enabled_disabled $shutdown_failed_log_sec_audits     = 'Disabled',
) {

  if $::os['family'] != 'windows' {
    fail("This class is only for Windows, not for ${::os['family']}")
  }

  # CIS 2.3.1.3
  if $accounts_guest_account_status != true {
    local_security_policy { 'Accounts: Guest account status':
      ensure       => present,
      policy_value => $accounts_guest_account_status,
    }
  }

  # CIS 2.3.1.4
  if $blank_passords_at_console != true {
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

  # CIS 2.3.
  local_security_policy { 'Accounts: Rename guest account':
    ensure       => present,
    policy_value => $guest_account_name$,
  }

  # CIS 2.3.
  if $override_audit_policy_cat_settings != true {
    local_security_policy { 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings':
      ensure       => present,
      policy_value => $override_audit_policy_cat_settings,
    }
  }

  # CIS 2.3.
  if $shutdown_failed_log_sec_audits != true {
    local_security_policy { 'Audit: Shut down system immediately if unable to log security audits':
      ensure       => present,
      policy_value => $shutdown_failed_log_sec_audits,
    }
  }

  # CIS 2.3.
  if $ != true {
    local_security_policy { '':
      ensure       => present,
      policy_value => join($, ','),
    }
  }

  # CIS 2.3.
  if $ != true {
    local_security_policy { '':
      ensure       => present,
      policy_value => join($, ','),
    }
  }

  # CIS 2.3.
  if $ != true {
    local_security_policy { '':
      ensure       => present,
      policy_value => join($, ','),
    }
  }

  # CIS 2.3.
  if $ != true {
    local_security_policy { '':
      ensure       => present,
      policy_value => join($, ','),
    }
  }

  # CIS 2.3.
  if $ != true {
    local_security_policy { '':
      ensure       => present,
      policy_value => join($, ','),
    }
  }

  # CIS 2.3.
  if $ != true {
    local_security_policy { '':
      ensure       => present,
      policy_value => join($, ','),
    }
  }

  # CIS 2.3.
  if $ != true {
    local_security_policy { '':
      ensure       => present,
      policy_value => join($, ','),
    }
  }

  # CIS 2.3.
  if $ != true {
    local_security_policy { '':
      ensure       => present,
      policy_value => join($, ','),
    }
  }


}
