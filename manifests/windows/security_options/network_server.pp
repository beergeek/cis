#
class cis::windows::security_options::network_server (
  Boolean $is_domain_controller                         = false,
  Integer[1, 15] $suspend_session_on_idle_minutes       = 15,
  Cis::Enabled_disabled $sign_comms_always              = 'Enabled',
  Cis::Enabled_disabled $sign_comms_client_agrees       = 'Enabled',
  Cis::Enabled_disabled $disconnect_logon_expires       = 'Enabled',
  Cis::Spn_valid $spn_tgt_valid_lvl                     = 'Accept if provided by client',
  Cis::Enabled_disabled $send_unencrypted_password_smb  = 'Disabled',
) {

  if $::os['family'] != 'windows' {
    fail("This class is only for Windows, not for ${::os['family']}")
  }

  # CIS 2.3.9.1
  if $suspend_session_on_idle_minutes != false {
    local_security_policy { 'Microsoft network server: Amount of idle time required before suspending session':
      ensure       => present,
      policy_value => String($suspend_session_on_idle_minutes),
    }
  }

  # CIS 2.3.9.2
  if $sign_comms_always != false {
    local_security_policy { 'Microsoft network server: Digitally sign communications (always)':
      ensure       => present,
      policy_value => $sign_comms_always,
    }
  }

  # CIS 2.3.9.3
  if $sign_comms_client_agrees != false {
    local_security_policy { 'Microsoft network server: Digitally sign communications (if client agrees)':
      ensure       => present,
      policy_value => $sign_comms_client_agrees,
    }
  }

  # CIS 2.3.9.4
  if $disconnect_logon_expires != false {
    local_security_policy { 'Microsoft network server: Disconnect clients when logon hours expire':
      ensure       => present,
      policy_value => $disconnect_logon_expires,
    }
  }

  # CIS 2.3.9.5
  if $spn_tgt_valid_lvl != false and $is_domain_controller == false {
    local_security_policy { 'Microsoft network server: Server SPN target name validation level':
      ensure       => present,
      policy_value => $spn_tgt_valid_lvl,
    }
  }
}
