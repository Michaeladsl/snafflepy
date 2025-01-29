import os
import sys
import logging
from ldap3 import Server, Connection, DSA

from .utilities import *
from .classifier import *
from .errors import *

log = logging.getLogger('snafflepy')


def begin_snaffle(options):
    snaff_rules = Rules()
    snaff_rules.prepare_classifiers()

    print("Beginning the snaffle...")

    # Load credentials from file or use -u and -p if provided
    credential_list = []
    if options.creds_file:
        try:
            with open(options.creds_file, 'r') as f:
                for line in f:
                    parts = line.strip().split(":", 1)
                    if len(parts) == 2:
                        username, password = parts
                        credential_list.append((username, password))
        except Exception as e:
            log.error(f"Failed to read credentials file: {e}")
            sys.exit(2)
    else:
        credential_list.append((options.username, options.password))  # Use provided single credentials

    for username, password in credential_list:
        log.info(f"Trying credentials: {username}")

        options.username = username  # Pass credentials directly to -u
        options.password = password  # Pass credentials directly to -p

        # Attempt LDAP authentication (if applicable)
        login = None
        if options.domain:
            try:
                login = access_ldap_server(options.targets[0], username, password)
                if login:
                    log.info(f"Successful LDAP authentication with {username}")
            except Exception as e:
                log.warning(f"LDAP authentication failed for {username}: {e}")
                login = None  # Prevent LDAP errors from stopping the process

        # If LDAP failed but domain discovery isn't required, continue
        if options.disable_computer_discovery or login:
            domain_names = []
            if login:
                domain_names = list_computers(login, options.domain)
            targets = options.targets + domain_names
        else:
            log.error(f"Skipping {username}: No valid authentication method.")
            continue  # Skip to next credential set

        # Create user-specific output directory
        user_output_folder = os.path.join("remotefiles", username)
        os.makedirs(user_output_folder, exist_ok=True)

        print(f"\n{'='*50}\nShares accessible by {username}\n{'='*50}")

        for target in targets:
            log.info(f"Scanning {target} with credentials {username}")

            smb_client = SMBClient(target, username, password, options.domain, options.hash)
            if not smb_client.login():
                log.error(f"Unable to login to {target} with {username}")
                continue

            for share in smb_client.shares:
                if share in options.exclude_shares:
                    log.info(f"Skipping excluded share: {share}")
                    continue

                try:
                    files = smb_client.ls(share, "")

                    for file in files:
                        size = file.get_filesize()
                        name = file.get_longname()

                        if file.is_directory():
                            log.warning(f"Skipping directory: \\\\{target}\\{share}\\{name}")
                            continue

                        # Save files to user-specific folder
                        file = RemoteFile(name, share, target, size, smb_client, output_folder=user_output_folder)

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
                    log.error(f"Cannot list files at {share}: {e}")

    print("\nSnaffling complete!")
