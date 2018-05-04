# A class to manage Password Policies (Windows CIS 1.1)
#
# @summary A class to manage password policies. Covers CIS 1.1 Password Policy
#
# @param password_history Determines the number of unique new passwords before the password can be reused. Set to `false` to skip.
# @param password_max_age Determine the maximum age for a password. Set to `false` to skip.
# @param password_min_age Determine the minimum age before the password can be changed. Set to `false` to skip.
# @param password_min_length Determine the minimum length of a password. Set to `false` to skip.
# @param password_complexity Determine  if password complexity is enabled or disabled.
# @param password_reversible_encryption Determine if passwords are stored with reversible encryption.
#
# @example
#   With defaults as per the Standard
#   include cis::windows::account_policies::passwords
#
#   If you need to change the settings then you should exclude this class from `cis::windows`:
#   class { 'cis::windows':
#     excluded_classes => ['cis::windows::account_policies::passwords'],
#   }
#
#   Then set the parameters as requried for this class:
#   class { 'cis::windows::account_policies::passwords':
#     password_history => 50,
#   }
#
class cis::windows::account_policies::passwords (
  Variant[Integer[24], Boolean[false]] $password_history     = 24,
  Variant[Integer[60], Boolean[false]] $password_max_age     = 60,
  Variant[Integer[1], Boolean[false]] $password_min_age      = 1,
  Variant[Integer[14], Boolean[false]] $password_min_length  = 14,
  Cis::Enabled_disabled $password_complexity                 = 'Enabled',
  Cis::Enabled_disabled $password_reversible_encryption      = 'Disabled',
) {

  if $facts['os']['family'] != 'windows' {
    fail("This class is only for Windows, not for ${facts['os']['family']}")
  }

  # CIS 1.1.1
  if $password_history != false {
    local_security_policy { 'Enforce password history':
      ensure       => present,
      policy_value => String($password_history),
    }
  }

  # CIS 1.1.2
  if $password_max_age != false {
    local_security_policy { 'Maximum password age':
      ensure       => present,
      policy_value => String($password_max_age),
    }
  }

  # CIS 1.1.3
  if $password_min_age != false {
    local_security_policy { 'Minimum password age':
      ensure       => present,
      policy_value => String($password_min_age),
    }
  }

  # CIS 1.1.4
  if $password_min_length != false {
    local_security_policy { 'Minimum password length':
      ensure       => present,
      policy_value => String($password_min_length),
    }
  }

  # CIS 1.1.5
  if $password_complexity != false {
    local_security_policy { 'Password must meet complexity requirements':
      ensure       => present,
      policy_value => $password_complexity,
    }
  }

  # CIS 1.1.6
  if $password_reversible_encryption != false {
    local_security_policy { 'Store passwords using reversible encryption':
      ensure       => present,
      policy_value => $password_reversible_encryption,
    }
  }
}
