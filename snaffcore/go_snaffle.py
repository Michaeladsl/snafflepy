import sys
import logging
from ldap3 import ALL_ATTRIBUTES, Server, Connection, DSA, ALL, SUBTREE

from .utilities import *
from .classifier import *
from .errors import *

log = logging.getLogger('snafflepy')


def begin_snaffle(options):
    snaff_rules = Rules()
    snaff_rules.prepare_classifiers()

    print("Beginning the snaffle...")

    if not options.domain:
        options.domain = get_domain(options.targets[0])
        if options.domain == "":
            sys.exit(2)

    domain_names = []
    if options.disable_computer_discovery:
        log.info("Computer discovery is turned off. Snaffling will only occur on the host(s) specified.")

    else:
        login = access_ldap_server(
            options.targets[0], options.username, options.password)
        domain_names = list_computers(login, options.domain)
        for target in domain_names:
            log.info(f"Found {target}, adding to targets to snaffle...")
            try:
                options.targets.append(target)
            except Exception as e:
                log.debug(f"Exception: {e}")
                log.warning(f"Unable to add {target} to targets to snaffle")
                continue

    if options.go_loud:
        log.warning("[GO LOUD ACTIVATED] Enumerating all shares for all files...")
    if options.no_download:
        log.warning("[no-download] is turned on, skipping SSN check...")
        
    for target in options.targets:
        smb_client = SMBClient(
            target, options.username, options.password, options.domain, options.hash)
        if not smb_client.login():
            log.error(f"Unable to login to {target}")
            continue
        
        for share in smb_client.shares:
            if share in options.exclude_shares:  # FIXED: Checking share as a string
                log.info(f"Skipping excluded share: {share}")
                continue
        
            files = []
            try:
                if not options.go_loud:
                    if is_interest_share(share, snaff_rules) == False:
                        log.debug(f"{share} matched a Discard rule, skipping files inside of this share...")
                        continue
                        
                files = smb_client.ls(share, "")
        
                for file in files:
                    size = file.get_filesize()
                    name = file.get_longname()
                    
                    # Ensure we only attempt to get files, not directories
                    if file.is_directory():
                        log.warning(f"Skipping directory: \\\\{target}\\{share}\\{name}")
                        continue  # Skip directories
        
                    file = RemoteFile(name, share, target, size, smb_client)
        
                    if options.go_loud:
                        try:
                            if not options.no_download:
                                file.get(smb_client)
                            log.info(f"[File] \\\\{target}\\{share}\\{name}")
        
                        except FileRetrievalError as e:
                            add_err = True
                            try:
                                file.handle_download_error(file.name, e, options.go_loud, add_err)
                            except Exception as err:
                                log.error(f"Error handling download error: {err}")
        
            except FileListError as e:
                log.error(f"Cannot list files at {share} {e}")
