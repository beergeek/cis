#
class cis::windows::security_options::network_client (
  Cis::Enabled_disabled $sign_comms_always              = 'Enabled',
  Cis::Enabled_disabled $sign_comms_server_agrees       = 'Enabled',
  Cis::Enabled_disabled $send_unencrypted_password_smb  = 'Disabled',
) {

  if $facts['os']['family'] != 'windows' {
    fail("This class is only for Windows, not for ${facts['os']['family']}")
  }

  # CIS 2.3.8.1
  if $sign_comms_always != false {
    local_security_policy { 'Microsoft network client: Digitally sign communications (always)':
      ensure       => present,
      policy_value => $sign_comms_always,
    }
  }

  # CIS 2.3.8.2
  if $sign_comms_server_agrees != false {
    local_security_policy { 'Microsoft network client: Digitally sign communications (if server agrees)':
      ensure       => present,
      policy_value => $sign_comms_server_agrees,
    }
  }

  # CIS 2.3.8.3
  if $send_unencrypted_password_smb != false {
    local_security_policy { 'Microsoft network client: Send unencrypted password to third-party SMB servers':
      ensure       => present,
      policy_value => $send_unencrypted_password_smb,
    }
  }

}
