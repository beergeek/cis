# A class to manage User Rights (Windows CIS 2.1)
#
# @summary A class to manage User Rights (Windows CIS 2.1)
#
# @example
#   With defaults as per the Standard
#   include cis::windows
#
#   If you need to change the settings then you should exclude this class from `cis::windows`:
#   class { 'cis::windows':
#     excluded_classes => ['cis::windows::local_policies::user_rights'],
#   }
#
#   Then set the parameters as requried for this class:
#   class { 'cis::windows::local_policies::user_rights':
#     is_domain_controller => false,
#     backup_users         => ['Admininstrators','Backup Users'],
#   }
#
# @param is_domain_controller Changes several settings if `false`. Adds or removes users/groups as per the standard. Affects Standard 2.2.2, 2.2.6, 2.2.17, 2.2.22, and 2.2.29.
# @param enable_level_2 If selected also enables Level 2 protection for 2.2
# @param access_credential_manager Users that can access the Credential Manager as a trusted caller.
# @param allow_computer_network_access Which users that can access computers via the network
# @param act_as_part_of_os Allows a process to assume the identity of any user.
# @param add_workstations_to_domain Users that can add a workstation to the domain. Only valid if `is_domain_controller` is `false`.
# @param adjust_process_memory_quote Aallows a user to adjust the maximum amount of memory that is available to a process
# @param allow_log_on_locally Determines which users can interactively log on to computers in your environment.
# @param allow_log_on_rdp Determines which users or groups have the right to log on as a Terminal Services client
# @param backup_users Aallows users to circumvent file and directory permissions to back up the system.
# @param change_sys_time Determines which users and groups can change the time and date on the internal clock of the computers in your environment.
# @param change_tz etermines which users can change the time zone of the computer.
# @param change_pagefile Allows users to change the size of the pagefile.
# @param create_token_object Allows a process to create an access token, which may provide elevated rights to access sensitive data.
# @param create_global_objects Determines whether users can create global objects that are available to all sessions.
# @param create_perm_shared_objects Users who have the Create permanent shared objects user right could create new shared objects and expose sensitive data to the network.
# @param create_symbolic_links Determines which users can create symbolic links.
# @param debug_programs Determines which user accounts will have the right to attach a debugger to any process or to the kernel, which provides complete access to sensitive and critical operating system components.
# @param deny_computer_network_access This setting prohibits users from connecting to a computer from across the network, which would allow users to access and potentially modify data remotely.
# @param deny_log_on_as_batch This setting determines which accounts will not be able to log on to the computer as a batch job.
# @param deny_log_on_as_service This setting determines which service accounts are prevented from registering a process as a service.
# @param deny_local_log_on This setting determines which users are prevented from logging on at the computer.
# @param deny_log_on_rdp Determines whether users can log on as Terminal Services clients.
# @param trusted_delegation Allows users to change the Trusted for Delegation setting on a computer object in Active Directory.
# @param force_shutdwon_remote Aallows users to shut down Windows Vista-based computers from remote locations on the network.
# @param gen_security_audits Determines which users or processes can generate audit records in the Security log.
# @param impersonate_client Allows programs that run on behalf of a user to impersonate that user (or another specified account) so that they can act on behalf of the user.
# @param increase_schedule_priority Determines whether users can increase the base priority class of a process.
# @param manage_device_drivers Allows users to dynamically load a new device driver on a system.
# @param lock_pages_in_mem Allows a process to keep data in physical memory, which prevents the system from paging the data to virtual memory on disk.
# @param log_on_as_batch Allows accounts to log on using the task scheduler service.
# @param manage_audit_sec_logs Determines which users can change the auditing options for files and directories and clear the Security log.
# @param modify_object_label Determines which user accounts can modify the integrity label of objects, such as files, registry keys, or processes owned by other users.
# @param mod_hw_env_values Allows users to configure the system-wide environment variables that affect hardware configuration.
# @param perform_vol_maint Allows users to manage the system's volume or disk configuration, which could allow a user to delete a volume and cause data loss as well as a denial-ofservice condition.
# @param profile_single_proc Determines which users can use tools to monitor the performance of non-system processes.
# @param profile_sys_perf Allows users to use tools to view the performance of different system processes, which could be abused to allow attackers to determine a system's active processes and provide insight into the potential attack surface of the computer.
# @param replace_proc_lvl_token Allows one process or service to start another service or process with a different security access token, which can be used to modify the security access token of that sub-process and result in the escalation of privileges.
# @param restore_files_dirs Determines which users can bypass file, directory, registry, and other persistent object permissions when restoring backed up files and directories on computers that run Windows Vista in your environment.
# @param shutdown_sys Determines which users who are logged on locally to the computers in your environment can shut down the operating system with the Shut Down command.
# @param sync_dir_service_data Determines which users and groups have the authority to synchronize all directory service data.
# @param own_files_and_objects Allows users to take ownership of files, folders, registry keys, processes, or threads.
#
class cis::windows::local_policies::user_rights (
  Boolean $is_domain_controller                   = false,
  Boolean $enable_level_2                         = false,
  Cis::Array_false $access_credential_manager      = ['No One'],
  Cis::Array_false $allow_computer_network_access  = ['Administrators','Authenticated Users'],
  Cis::Array_false $act_as_part_of_os              = ['No One'],
  Cis::Array_false $add_workstations_to_domain     = ['Administrators'],
  Cis::Array_false $adjust_process_memory_quote    = ['Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE'],
  Cis::Array_false $allow_log_on_locally           = ['Administrators'],
  Cis::Array_false $allow_log_on_rdp               = ['Administrators','Remote Desktop Users'],
  Cis::Array_false $backup_users                   = ['Administrators'],
  Cis::Array_false $change_sys_time                = ['Administrators', 'LOCAL SERVICE'],
  Cis::Array_false $change_tz                      = ['Administrators', 'LOCAL SERVICE'],
  Cis::Array_false $change_pagefile                = ['Administrators'],
  Cis::Array_false $create_token_object            = ['No One'],
  Cis::Array_false $create_global_objects          = ['Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE'],
  Cis::Array_false $create_perm_shared_objects     = ['No One'],
  Cis::Array_false $create_symbolic_links          = ['Administrators'],
  Cis::Array_false $debug_programs                 = ['Administrators'],
  Cis::Array_false $deny_computer_network_access   = ['Guests', 'Local account', 'member of Administrators group'],
  Cis::Array_false $deny_log_on_as_batch           = ['Guests'],
  Cis::Array_false $deny_log_on_as_service         = ['Guests'],
  Cis::Array_false $deny_local_log_on              = ['Guests'],
  Cis::Array_false $deny_log_on_rdp                = ['Guests','Local account'],
  Cis::Array_false $trusted_delegation             = ['No One'],
  Cis::Array_false $force_shutdwon_remote          = ['Administrators'],
  Cis::Array_false $gen_security_audits            = ['LOCAL SERVICE', 'NETWORK SERVICE'],
  Cis::Array_false $impersonate_client             = ['Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE'],
  Cis::Array_false $increase_schedule_priority     = ['Administrators'],
  Cis::Array_false $manage_device_drivers          = ['Administrators'],
  Cis::Array_false $lock_pages_in_mem              = ['No One'],
  Cis::Array_false $log_on_as_batch                = ['Administrators',],
  Cis::Array_false $manage_audit_sec_logs          = ['Administrators'],
  Cis::Array_false $modify_object_label            = ['No One'],
  Cis::Array_false $mod_hw_env_values              = ['Administrators'],
  Cis::Array_false $perform_vol_maint              = ['Administrators'],
  Cis::Array_false $profile_single_proc            = ['Administrators'],
  Cis::Array_false $profile_sys_perf               = ['Administrators','NT SERVICE\WdiServiceHost'],
  Cis::Array_false $replace_proc_lvl_token         = ['LOCAL SERVICE', 'NETWORK SERVICE'],
  Cis::Array_false $restore_files_dirs             = ['Administrators'],
  Cis::Array_false $shutdown_sys                   = ['Administrators'],
  Cis::Array_false $sync_dir_service_data          = ['No One'],
  Cis::Array_false $own_files_and_objects          = ['Administrators'],
) {

  if $::os['family'] != 'windows' {
    fail("This class is only for Windows, not for ${::os['family']}")
  }

  if $is_domain_controller == true {
    $_allow_computer_network_access = $allow_computer_network_access + ['ENTERPRISE DOMAIN CONTROLLERS']
    $_allow_log_on_locally          = $allow_log_on_locally + ['ENTERPRISE DOMAIN CONTROLLERS']
    $_allow_log_on_rdp              = $allow_log_on_rdp - ['Remote Desktop Users']
    $_deny_computer_network_access  = $deny_computer_network_access - ['member of Administrators group']
    $_trusted_delegation            = $trusted_delegation - ['No One'] + ['Administrators']
  } else {
    $_allow_computer_network_access = $allow_computer_network_access
    $_allow_log_on_locally          = $allow_log_on_locally
    $_allow_log_on_rdp              = $allow_log_on_rdp
    $_deny_computer_network_access  = $deny_computer_network_access
    $_trusted_delegation            = $trusted_delegation
  }

  # CIS 2.2.1
  if $access_credential_manager != false {
    local_security_policy { 'Access Credential Manager as a trusted caller':
      ensure       => present,
      policy_value => join($access_credential_manager, ','),
    }
  }

  # CIS 2.2.2
  if $allow_computer_network_access != false {
    local_security_policy { 'Access this computer from the network':
      ensure       => present,
      policy_value => join($_allow_computer_network_access, ','),
    }
  }

  # CIS 2.2.3
  if $act_as_part_of_os != false {
    local_security_policy { 'Act as part of the operating system':
      ensure       => present,
      policy_value => join($act_as_part_of_os, ','),
    }
  }

  # CIS 2.2.4
  if $add_workstations_to_domain != false {
    local_security_policy { 'Add workstations to domain':
      ensure       => present,
      policy_value => join($add_workstations_to_domain, ','),
    }
  }

  # CIS 2.2.5
  if $adjust_process_memory_quote  != false {
    local_security_policy { 'Adjust memory quotas for a process':
      ensure       => present,
      policy_value => join($adjust_process_memory_quote, ','),
    }
  }

  # CIS 2.2.6
  if $allow_log_on_locally  != false {
    local_security_policy { 'Allow log on locally':
      ensure       => present,
      policy_value => join($_allow_log_on_locally, ','),
    }
  }

  # CIS 2.2.7
  if $allow_log_on_rdp  != false {
    local_security_policy { 'Allow log on through Remote Desktop Services':
      ensure       => present,
      policy_value => join($_allow_log_on_rdp, ','),
    }
  }

  # CIS 2.2.8
  if $backup_users != false {
    local_security_policy { 'Back up files and directories':
      ensure       => present,
      policy_value => join($backup_users, ','),
    }
  }

  # CIS 2.2.9
  if $change_sys_time  != false {
    local_security_policy { 'Change the system time':
      ensure       => present,
      policy_value => join($change_sys_time, ','),
    }
  }

  # CIS 2.2.10
  if $change_tz  != false {
    local_security_policy { 'Change the time zone':
      ensure       => present,
      policy_value => join($change_tz, ','),
    }
  }

  # CIS 2.2.11
  if $change_pagefile  != false {
    local_security_policy { 'Create a pagefile':
      ensure       => present,
      policy_value => join($change_pagefile, ','),
    }
  }

  # CIS 2.2.12
  if $create_token_object  != false {
    local_security_policy { 'Create a token object':
      ensure       => present,
      policy_value => join($create_token_object, ','),
    }
  }

  # CIS 2.2.13
  if $create_global_objects  != false {
    local_security_policy { 'Create global objects':
      ensure       => present,
      policy_value => join($create_global_objects, ','),
    }
  }

  # CIS 2.2.14
  if $create_perm_shared_objects  != false {
    local_security_policy { 'Create permanent shared objects':
      ensure       => present,
      policy_value => join($create_perm_shared_objects, ','),
    }
  }

  # CIS 2.2.15
  if $create_symbolic_links  != false {
    local_security_policy { 'Create symbolic links':
      ensure       => present,
      policy_value => join($create_symbolic_links, ','),
    }
  }

  # CIS 2.2.16
  if $debug_programs  != false {
    local_security_policy { 'Debug programs':
      ensure       => present,
      policy_value => join($debug_programs, ','),
    }
  }

  # CIS 2.2.17
  if $deny_computer_network_access  != false {
    local_security_policy { 'Deny access to this computer from the network':
      ensure       => present,
      policy_value => join($_deny_computer_network_access, ','),
    }
  }

  # CIS 2.2.18
  if $deny_log_on_as_batch  != false {
    local_security_policy { 'Deny log on as a batch job':
      ensure       => present,
      policy_value => join($deny_log_on_as_batch, ','),
    }
  }

  # CIS 2.2.19
  if $deny_log_on_as_service  != false {
    local_security_policy { 'Deny log on as a service':
      ensure       => present,
      policy_value => join($deny_log_on_as_service, ','),
    }
  }

  # CIS 2.2.20
  if $deny_local_log_on  != false {
    local_security_policy { 'Deny log on locally':
      ensure       => present,
      policy_value => join($deny_local_log_on, ','),
    }
  }

    # CIS 2.2.21
    if $deny_log_on_rdp  != false {
      local_security_policy { 'Deny log on through Remote Desktop Services':
        ensure       => present,
        policy_value => join($deny_log_on_rdp, ','),
      }
    }

    # CIS 2.2.22
    if $trusted_delegation  != false {
      local_security_policy { 'Enable computer and user accounts to be trusted for delegation':
        ensure       => present,
        policy_value => join($_trusted_delegation, ','),
      }
    }

    # CIS 2.2.23
    if $force_shutdwon_remote  != false {
      local_security_policy { 'Force shutdown from a remote system':
        ensure       => present,
        policy_value => join($force_shutdwon_remote, ','),
      }
    }

    # CIS 2.2.24
    if $gen_security_audits  != false {
      local_security_policy { 'Generate security audits':
        ensure       => present,
        policy_value => join($gen_security_audits, ',')
      }
    }

    # CIS 2.2.25
    if $impersonate_client  != false {
      local_security_policy { 'Impersonate a client after authentication':
        ensure       => present,
        policy_value => join($impersonate_client, ',')
      }
    }

    # CIS 2.2.26
    if $increase_schedule_priority  != false {
      local_security_policy { 'Increase scheduling priority':
        ensure       => present,
        policy_value => join($increase_schedule_priority, ','),
      }
    }

    # CIS 2.2.27
    if $manage_device_drivers  != false {
      local_security_policy { 'Load and unload device drivers':
        ensure       => present,
        policy_value => join($manage_device_drivers, ','),
      }
    }

    # CIS 2.2.28
    if $lock_pages_in_mem  != false {
      local_security_policy { 'Lock pages in memory':
        ensure       => present,
        policy_value => join($lock_pages_in_mem, ','),
      }
    }

    # CIS 2.2.29
    if $log_on_as_batch  != false and $enable_level_2 == true and $is_domain_controller == true {
      local_security_policy { 'Log on as a batch job':
        ensure       => present,
        policy_value => join($log_on_as_batch, ','),
      }
    }

    # CIS 2.2.30
    if $manage_audit_sec_logs  != false {
      local_security_policy { 'Manage auditing and security log':
        ensure       => present,
        policy_value => join($manage_audit_sec_logs, ','),
      }
    }

    # CIS 2.2.31
    if $modify_object_label  != false {
      local_security_policy { 'Modify an object label':
        ensure       => present,
        policy_value => join($modify_object_label, ','),
      }
    }

    # CIS 2.2.32
    if $mod_hw_env_values  != false {
      local_security_policy { 'Modify firmware environment values':
        ensure       => present,
        policy_value => join($mod_hw_env_values, ','),
      }
    }

    # CIS 2.2.33
    if $perform_vol_maint  != false {
      local_security_policy { 'Perform volume maintenance tasks':
        ensure       => present,
        policy_value => join($perform_vol_maint, ','),
      }
    }

    # CIS 2.2.34
    if $profile_single_proc  != false {
      local_security_policy { 'Profile single process':
        ensure       => present,
        policy_value => join($profile_single_proc, ','),
      }
    }

    # CIS 2.2.35
    if $profile_sys_perf  != false {
      local_security_policy { 'Profile system performance':
        ensure       => present,
        policy_value => join($profile_sys_perf, ','),
      }
    }

    # CIS 2.2.36
    if $replace_proc_lvl_token  != false {
      local_security_policy { 'Replace a process level token':
        ensure       => present,
        policy_value => join($replace_proc_lvl_token, ','),
      }
    }

    # CIS 2.2.37
    if $restore_files_dirs  != false {
      local_security_policy { 'Restore files and directories':
        ensure       => present,
        policy_value => join($restore_files_dirs, ','),
      }
    }

    # CIS 2.2.38
    if $shutdown_sys  != false {
      local_security_policy { 'Shut down the system':
        ensure       => present,
        policy_value => join($shutdown_sys, ','),
      }
    }

    # CIS 2.2.39
    if $sync_dir_service_data  != false {
      local_security_policy { 'Synchronize directory service data':
        ensure       => present,
        policy_value => join($sync_dir_service_data, ','),
      }
    }

    # CIS 2.2.40
    if $own_files_and_objects  != false {
      local_security_policy { 'Take ownership of files or other objects':
        ensure       => present,
        policy_value => join($own_files_and_objects, ','),
      }
    }
}
