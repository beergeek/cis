#
class cis::windows::security_options::audit (
  Cis::Enabled_disabled $force_audit_subcat_settings = 'Enabled',
  Cis::Enabled_disabled $shutdown_unable_to_log      = 'Disabled',
) {

  if $::os['family'] != 'windows' {
    fail("This class is only for Windows, not for ${::os['family']}")
  }

  # CIS 2.3.2.1
  if $force_audit_subcat_settings != false {
    local_security_policy { 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings':
      ensure       => present,
      policy_value => $force_audit_subcat_settings,
    }
  }

  # CIS 2.3.2.2
  if $shutdown_unable_to_log != false {
    local_security_policy { 'Audit: Shut down system immediately if unable to log security audits':
      ensure       => present,
      policy_value => $shutdown_unable_to_log,
    }
  }
}
