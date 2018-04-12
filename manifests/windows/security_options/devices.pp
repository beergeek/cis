#
class cis::windows::security_options::devices (
  Cis::Array_false $format_eject_devices_users        = ['Administrators'],
  Cis::Enabled_disabled $prevent_users_print_drivers = 'Enabled',
) {

  if $::os['family'] != 'windows' {
    fail("This class is only for Windows, not for ${::os['family']}")
  }

  # CIS 2.3.4.1
  if $format_eject_devices_users != false {
    local_security_policy { 'Devices: Allowed to format and eject removable media':
      ensure       => present,
      policy_value => join($format_eject_devices_users, ','),
    }
  }

  # CIS 2.3.4.2
  if $prevent_users_print_drivers != false {
    local_security_policy { 'Devices: Prevent users from installing printer drivers':
      ensure       => present,
      policy_value => $prevent_users_print_drivers,
    }
  }
}
