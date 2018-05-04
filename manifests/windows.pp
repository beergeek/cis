# Abstract class to manage CIS for MS WIndows Server 2012R2 v2.2.1 and 2016 v1.0.0
#
# @summary class to manage CIS for MS WIndows Server 2012R2 v2.2.1 and 2016 v1.0.0.
# By default all sections of the Standard are included with the recommended default settings.
#
# @param excluded_sections By default all classes for this standard are included with the default settings as per the Standard.
# If you need to adjust a setting or settings within one of the sections of the Standard include the fully scoped name of the class
# within this array and then instantiate that class separately.
#
# @example
#   # To accept all the defaults as per the Standard just include the class:
#   include cis::windows
#
#   # To change the setting of a particular section exclude the class you want to change:
#   class { 'cis::windows':
#     excluded_sections => ['cis::windows::account_policies::lockout'],
#   }
#
#   # Then instantiate the excluded class with the parameters you need:
#   class { 'cis::windows::account_policies::lockout':
#     lockout_invalid_attempts => 5,
#   }
#
class cis::windows (
  Boolean $is_domain_controller,
  Cis::String_false $admin_account_name,
  Cis::String_false $guest_account_name,
  Cis::String_false $logon_message,
  Cis::String_false $logon_title,
  Optional[Array[String]] $excluded_sections = [],
) {

  if $facts['os']['family'] != 'windows' {
    fail("This class is only for Windows, not for ${facts['os']['family']}")
  }

  if ! member($excluded_sections, 'cis::windows::account_policies::lockout') {
    include cis::windows::account_policies::lockout
  }

    if ! member($excluded_sections, 'cis::windows::account_policies::passwords') {
      include cis::windows::account_policies::passwords
    }

    if ! member($excluded_sections, 'cis::windows::local_policies::user_rights') {
      class { 'cis::windows::local_policies::user_rights':
        is_domain_controller => $is_domain_controller,
      }
    }

    if ! member($excluded_sections, 'cis::windows::security_options::accounts') {
      class { 'cis::windows::security_options::accounts':
        admin_account_name => $admin_account_name,
        guest_account_name => $guest_account_name,
      }
    }

    if ! member($excluded_sections, 'cis::windows::security_options::audit') {
      include cis::windows::security_options::audit
    }

    if ! member($excluded_sections, 'cis::windows::security_options::devices') {
      include cis::windows::security_options::devices
    }

    if ! member($excluded_sections, 'cis::windows::security_options::domain_controller') {
      include cis::windows::security_options::domain_controller
    }

  #  if ! member($excluded_sections, '') {
  #    include cis::windows::
  #  }
  #
  #  if ! member($excluded_sections, '') {
  #    include cis::windows::
  #  }
  #
  #  if ! member($excluded_sections, '') {
  #    include cis::windows::
  #  }

}
