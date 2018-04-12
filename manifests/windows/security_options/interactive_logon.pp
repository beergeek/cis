#
class cis::windows::security_options::interactive_logon (
  String $logon_message,
  Cis::Enabled_disabled $do_not_display_last_name = 'Enabled',
  Cis::Enabled_disabled $do_not_require_ctl_alt_del = 'Disabled',
  Integer[1, 900] $machine_inactivity_limit         = 900,

) {

  if $::os['family'] != 'windows' {
    fail("This class is only for Windows, not for ${::os['family']}")
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

  #  # CIS 2.3.7.
  #  if $ != false {
  #    local_security_policy { '':
  #      ensure       => present,
  #      policy_value => $,
  #    }
  #  }
  #
  #  # CIS 2.3.7.
  #  if $ != false {
  #    local_security_policy { '':
  #      ensure       => present,
  #      policy_value => $,
  #    }
  #  }
  #
  #  # CIS 2.3.7.
  #  if $ != false {
  #    local_security_policy { '':
  #      ensure       => present,
  #      policy_value => $,
  #    }
  #  }

}
