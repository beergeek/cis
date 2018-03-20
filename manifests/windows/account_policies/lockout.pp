# Class to manage Account Lockout Policy (Windows CIS 1.2)
#
# @summary A class to manage the Account Lockout Policeis (Windows CIS 1.2)
#
# @param lockout_duration Time in minutes that lockout will occur. Can be skipped if set to `true`.
# @param lockout_invalid_attempts Number of unsuccessful attempts to log in before being locked  out. Can be skipped if set to `true`.
# @param lockout_reset_time Time in minutes before the lockout attempt count is reset to 0. Must be less than or equal to lockout_duration, if set. Can be skipped if set to `true`.
#
# @example
#
#
class cis::windows::account_policies::lockout (
  Variant[Integer[15], Boolean[true]] $lockout_duration = 15,
  Variant[Integer[1,10], Boolean[true]] $lockout_invalid_attempts = 10,
  Variant[Integer[15], Boolean[true]] $lockout_reset_time = 15,
) {

  if $::os['family'] != 'windows' {
    fail("This class is only for Windows, not for ${::os['family']}")
  }

  # CIS 1.2.1
  if $lockout_duration != true {
    local_security_policy { 'Account lockout duration':
      ensure       => present,
      policy_value => $lockout_duration,
    }
  }

  # CIS 1.2
  if $lockout_invalid_attempts != true {
    local_security_policy { 'Account lockout threshold':
      ensure       => present,
      policy_value => $lockout_invalid_attempts,
    }
  }

  # CIS 1.2
  if $lockout_reset_time != true {
    if $lockout_duration <= $lockout_reset_time {
      local_security_policy { 'Reset account lockout counter after':
        ensure       => present,
        policy_value => $lockout_reset_time,
      }
    } else {
      fail('$lockout_duration must be less than or equal to $lockout_reset_time')
    }
  }
}
