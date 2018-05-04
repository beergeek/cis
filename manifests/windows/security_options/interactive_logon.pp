#
class cis::windows::security_options::interactive_logon (
  Cis::String_false $logon_message,
  Cis::String_false $logon_title,
  Boolean $is_domain_controller                         = false,
  Boolean $enable_level_2                               = false,
  Cis::Enabled_disabled $do_not_display_last_name       = 'Enabled',
  Cis::Enabled_disabled $do_not_require_ctl_alt_del     = 'Disabled',
  Integer[1, 900] $machine_inactivity_limit             = 900,
  Integer[0, 4] $no_cached_previous_logons              = 4,
  Integer[5, 14] $password_change_warning_days          = 10,
  Cis::Enabled_disabled $require_dc_auth_unlock_machine = 'Enabled',
  Cis::Smartcard_options $smartcard_remove_behaviour    = 'Lock Workstation',
) {

  if $facts['os']['family'] != 'windows' {
    fail("This class is only for Windows, not for ${facts['os']['family']}")
  }

  # CIS 2.3.7.1
  if $do_not_display_last_name != false {
    local_security_policy { 'Interactive logon: Do not display last user name':
      ensure       => present,
      policy_value => $do_not_display_last_name,
    }
  }

  # CIS 2.3.7.2
  if $do_not_require_ctl_alt_del != false {
    local_security_policy { 'Interactive logon: Do not require CTRL+ALT+DEL':
      ensure       => present,
      policy_value => $do_not_require_ctl_alt_del,
    }
  }

  # CIS 2.3.7.3
  if $machine_inactivity_limit != false {
    local_security_policy { 'Interactive logon: Machine inactivity limit':
      ensure       => present,
      policy_value => $machine_inactivity_limit,
    }
  }

  # CIS 2.3.7.4
  if $logon_message != false {
    local_security_policy { 'Interactive logon: Message text for users attempting to log on':
      ensure       => present,
      policy_value => $logon_message,
    }
  }

  # CIS 2.3.7.5
  if $logon_title != false {
    local_security_policy { 'Interactive logon: Message title for users attempting to log on':
      ensure       => present,
      policy_value => $logon_title,
    }
  }

  # CIS 2.3.7.6
  if $no_cached_previous_logons != false and $enable_level_2 == true {
    local_security_policy { 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)':
      ensure       => present,
      policy_value => String($no_cached_previous_logons),
    }
  }

  # CIS 2.3.7.7
  if $password_change_warning_days != false {
    local_security_policy { 'Interactive logon: Prompt user to change password before expiration':
      ensure       => present,
      policy_value => String($password_change_warning_days),
    }
  }

  # CIS 2.3.7.8
  if $require_dc_auth_unlock_machine != false and $is_domain_controller == false {
    local_security_policy { 'Interactive logon: Require Domain Controller Authentication to unlock workstation':
      ensure       => present,
      policy_value => $require_dc_auth_unlock_machine,
    }
  }

  # CIS 2.3.7.9
  if $smartcard_remove_behaviour != false {
    local_security_policy { 'Interactive logon: Smart card removal behavior':
      ensure       => present,
      policy_value => $smartcard_remove_behaviour,
    }
  }

}
