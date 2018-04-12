#
class cis::windows::security_options::domain_controller (
  Cis::Enabled_disabled $operators_schedule_tasks       = 'Disabled',
  Cis::Require_none $ldap_signing                       = 'Require signing',
  Cis::Enabled_disabled $refuse_machine_password_change = 'Disabled',
) {

  if $::os['family'] != 'windows' {
    fail("This class is only for Windows, not for ${::os['family']}")
  }

  # CIS 2.3.5.1
  if $operators_schedule_tasks != false {
    local_security_policy { 'Domain controller: Allow server operators to schedule tasks':
      ensure       => present,
      policy_value => $operators_schedule_tasks,
    }
  }

  # CIS 2.3.5.2
  if $ldap_signing != false {
    local_security_policy { 'Domain controller: LDAP server signing requirements':
      ensure       => present,
      policy_value => $ldap_signing,
    }
  }

  # CIS 2.3.5.3
  if $refuse_machine_password_change != false {
    local_security_policy { 'Domain controller: Refuse machine account password changes':
      ensure       => present,
      policy_value => $refuse_machine_password_change,
    }
  }
}
