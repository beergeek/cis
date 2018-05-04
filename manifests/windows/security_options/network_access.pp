# A class to manage CIS 
#
# @summary
#
# @param is_domain_controller A boolean value to determine if the node is a domain_controller or not. Selecting `true` will change the rules enforced.
# @param allow_anonymous_sid_translation 
# @param disallow_anonymous_enum_sam_accounts
# @param disallow_anonymous_enum_sam_accounts_shares
# @param named_pipes_access_anonymous
#
# @example
# include cis::windows::security_options::network_access
# or
# class { 'cis::windows::security_options::network_access':
#  is_domain_controller => true,
# }
#
class cis::windows::security_options::network_access (
  Boolean $is_domain_controller                                       = false,
  Cis::Enabled_disabled $allow_anonymous_sid_translation              = 'Disabled',
  Cis::Enabled_disabled $disallow_anonymous_enum_sam_accounts         = 'Enabled',
  Cis::Enabled_disabled $disallow_anonymous_enum_sam_accounts_shares  = 'Enabled',
  Cis::Enabled_disabled $disallow_storage_net_passwords_creds         = 'Enabled',
  Cis::Enabled_disabled $everyone_access_anonymous_users              = 'Disabled',
  Cis::Array_false $named_pipes_access_anonymous                      = ['None'],
) {

  if $facts['os']['family'] != 'windows' {
    fail("This class is only for Windows, not for ${facts['os']['family']}")
  }

  if $is_domain_controller == true and $named_pipes_access_anonymous.size == 1 and $named_pipes_access_anonymous[0] == 'None' {
    $_named_pipes_access_anonymous = ['Netlogon','samr','lsarpc']
  } else {
    $_named_pipes_access_anonymous = $named_pipes_access_anonymous
  }

  # CIS 2.3.10.1
  if $allow_anonymous_sid_translation != false {
    local_security_policy { 'Network access: Allow anonymous SID/Name translation':
      ensure       => present,
      policy_value => $allow_anonymous_sid_translation,
    }
  }

  # CIS 2.3.10.2
  if $disallow_anonymous_enum_sam_accounts != false and $is_domain_controller != true {
    local_security_policy { 'Network access: Do not allow anonymous enumeration of SAM accounts':
      ensure       => present,
      policy_value => $disallow_anonymous_enum_sam_accounts,
    }
  }

  # CIS 2.3.10.3
  if $disallow_anonymous_enum_sam_accounts_shares != false and $is_domain_controller != true{
    local_security_policy { 'Network access: Do not allow anonymous enumeration of SAM accounts and shares':
      ensure       => present,
      policy_value => $disallow_anonymous_enum_sam_accounts_shares,
    }
  }

  # CIS 2.3.10.4
  if $disallow_storage_net_passwords_creds != false {
    local_security_policy { 'Network access: Do not allow storage of passwords and credentials for network authentication':
      ensure       => present,
      policy_value => $disallow_storage_net_passwords_creds,
    }
  }

  # CIS 2.3.10.5
  if $everyone_access_anonymous_users != false {
    local_security_policy { 'Network access: Let Everyone permissions apply to anonymous users':
      ensure       => present,
      policy_value => $everyone_access_anonymous_users,
    }
  }

  # CIS 2.3.10.6
  if $named_pipes_access_anonymous != false {
    local_security_policy { 'Network access: Named Pipes that can be accessed anonymously':
      ensure       => present,
      policy_value => $_named_pipes_access_anonymous,
    }
  }

  #  # CIS 2.3.10.
  #  if $ != false {
  #    local_security_policy { '':
  #      ensure       => present,
  #      policy_value => $,
  #    }
  #  }
  #
  #  # CIS 2.3.10.
  #  if $ != false {
  #    local_security_policy { '':
  #      ensure       => present,
  #      policy_value => $,
  #    }
  #  }


}
