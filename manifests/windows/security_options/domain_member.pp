#
class cis::windows::security_options::domain_member (
  Cis::Enabled_disabled $encrypt_sign_data                = 'Enabled',
  Cis::Enabled_disabled $encrypt_channel_data             = 'Enabled',
  Cis::Enabled_disabled $sign_channel_data                = 'Enabled',
  Cis::Enabled_disabled $disable_machine_password_change  = 'Disabled',
  Integer[1, 30] $machine_max_password_age                = 30,
  Cis::Enabled_disabled $require_strong_session_key       = 'Enabled',
) {

  if $::os['family'] != 'windows' {
    fail("This class is only for Windows, not for ${::os['family']}")
  }

  # CIS 2.3.6.1
  if $encrypt_sign_data != false {
    local_security_policy { 'Domain member: Digitally encrypt or sign secure channel data (always)':
      ensure       => present,
      policy_value => $encrypt_sign_data,
    }
  }

  # CIS 2.3.6.2
  if $encrypt_channel_data != false {
    local_security_policy { 'Domain member: Digitally encrypt secure channel data (when possible)':
      ensure       => present,
      policy_value => $encrypt_channel_data,
    }
  }

  # CIS 2.3.6.3
  if $sign_channel_data != false {
    local_security_policy { 'Domain member: Digitally sign secure channel data (when possible)':
      ensure       => present,
      policy_value => $sign_channel_data,
    }
  }

  # CIS 2.3.6.4
  if $disable_machine_password_change != false {
    local_security_policy { 'Domain member: Disable machine account password changes':
      ensure       => present,
      policy_value => $disable_machine_password_change,
    }
  }

  # CIS 2.3.6.5
  if $machine_max_password_age != false {
    local_security_policy { 'Domain member: Maximum machine account password age':
      ensure       => present,
      policy_value => String($machine_max_password_age),
    }
  }

  # CIS 2.3.6.6
  if $require_strong_session_key != false {
    local_security_policy { 'Domain member: Require strong (Windows 2000 or later) session key':
      ensure       => present,
      policy_value => $require_strong_session_key,
    }
  }
}
