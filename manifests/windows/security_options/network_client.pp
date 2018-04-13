#
class cis::windows::security_options::network_client (
) {

  if $::os['family'] != 'windows' {
    fail("This class is only for Windows, not for ${::os['family']}")
  }

  # CIS 2.3.8.
  if $ != false {
    local_security_policy { '':
      ensure       => present,
      policy_value => $,
    }
  }

  # CIS 2.3.8.
  if $ != false {
    local_security_policy { '':
      ensure       => present,
      policy_value => $,
    }
  }

  # CIS 2.3.8.
  if $ != false {
    local_security_policy { '':
      ensure       => present,
      policy_value => $,
    }
  }
}
