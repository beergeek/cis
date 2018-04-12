# Class to manage Account Lockout Policy (Windows CIS 1.2)
#
# @summary A class to manage the Account Lockout Policeis (Windows CIS 1.2). If the recommended defaults satisfy your requirements this class should be instantiated from `cis::windows` class and not by calling this class directory.
#
# @param lockout_duration Time in minutes that lockout will occur. Can be skipped if set to `false`.
# @param lockout_invalid_attempts Number of unsuccessful attempts to log in before being locked  out. Can be skipped if set to `false`.
# @param lockout_reset_time Time in minutes before the lockout attempt count is reset to 0. If `lockout_invalid_attempts` is set, the value must be less than or equal to `lockout_duration`. Can be skipped if set to `false`.
#
# @example
#   With defaults as per the Standard
#   include cis::windows
#
#   If you need to change the settings then you should exclude this class from `cis::windows`:
#   class { 'cis::windows':
#     excluded_classes => ['cis::windows::account_policies::lockout'],
#   }
#
#   Then set the parameters as requried for this class:
#   class { 'cis::windows::account_policies::lockout':
#     lockout_invalid_attempts => 5,
#   }
#
class cis::windows::account_policies::lockout (
  Variant[Integer[15], Boolean[false]] $lockout_duration            = 15,
  Variant[Integer[1,10], Boolean[false]] $lockout_invalid_attempts  = 10,
  Variant[Integer[15], Boolean[false]] $lockout_reset_time          = 15,
) {

  if $::os['family'] != 'windows' {
    fail("This class is only for Windows, not for ${::os['family']}")
  }

  # CIS 1.2.1
  if $lockout_duration != false {
    local_security_policy { 'Account lockout duration':
      ensure       => present,
      policy_value => String($lockout_duration),
    }
  }

  # CIS 1.2
  if $lockout_invalid_attempts != false {
    local_security_policy { 'Account lockout threshold':
      ensure       => present,
      policy_value => String($lockout_invalid_attempts),
    }
  }

  # CIS 1.2
  if $lockout_reset_time != false {
    if $lockout_invalid_attempts == false or $lockout_reset_time <= $lockout_duration {
      local_security_policy { 'Reset account lockout counter after':
        ensure       => present,
        policy_value => String($lockout_reset_time),
      }
    } else {
      fail('$lockout_duration must be less than or equal to $lockout_reset_time')
    }
  }
}
