import os
import csv
import json
from collections import defaultdict

# Define the base directory
base_directory = '/home/ub/Documents/Ransomware samples and analysis report/ransomware samples from github/'

# Initialize defaultdict for JSON keys
all_json_keys = defaultdict(list)

# Define the output CSV path
output_csv_path = '/home/ub/Desktop/script_for_analysis/output.csv'

# Initialize a list to store rows of data
all_rows = []

# Column headers
columns = [
    "virustotal_positives", "virustotal_normalized", "extracted_files", "buffer_data", 
    "suricata_http", "suricata_alerts", "dropped_files", "processes", 
    "file_created", "file_deleted", "file_moved", "file_written", 
    "file_copied", "file_opened", "file_failed", "file_read", "file_recreated", 
    "directory_created", "directory_deleted", "directory_moved", "directory_enumerated", 
    "regkey_written", "regkey_opened", "regkey_deleted", "regkey_read", 
    "dll_loaded", "mutex", "connects_host", "command_line", "fetches_url", 
    "yara_markcount", "total_ttp_count"
]

names_to_check = [
    "locates_browser", "persistence_ads", "locker_taskmgr", "inject_thread", "generates_crypto_key", 
    "creates_exe", "exe_appdata", "antivm_generic_cpu", "persistence_autorun", "terminates_remote_process", 
    "dumped_buffer2", "trojan_dapato", "ransomware_wbadmin", "ransomware_appends_extensions", 
    "modifies_firefox_configuration", "ransomware_extensions", "antiav_servicestop", "spreading_autoruninf", 
    "infostealer_ftp", "ransomware_mass_file_delete", "win_hook", "rat_hupigon", "creates_hidden_file", 
    "creates_service", "creates_shortcut", "recon_beacon", "antisandbox_sleep", "creates_doc", 
    "ransomware_shadowcopy", "allocates_rwx", "clears_event_logs", "network_http", "infostealer_keylogger", 
    "process_interest", "antivm_disk_size", "antivm_memory_available", "antisandbox_cuckoo_files", 
    "modfies_proxy_wpad", "modifies_certificates", "modifies_boot_config", "modifies_certificates", 
    "modify_uac_prompt", "disables_security", "injection_process_search", "antivm_network_adapters", 
    "priviledge_luid_check", "dumped_buffer", "antivm_generic_services", "antisandbox_foregroundwindows", 
    "overwites_files", "antivm_vbox_devices", "peid_packer", "generates_crypto_key", "antivm_queries_computername", 
    "console_output", "raises_exception", "suspicious_process", "stealth_window", 
    "ransomware_file_moves", "ransomware_appends_extensions", "recon_fingerprint", "ransomware_dropped_files"
]

rules_to_check = [
    "Destructive_Ransomware*",  # Will match any "Destructive_Ransomware" prefix
    "spreading_share",
    "win_mutex",
    "win_registry",
    "win_files_operation",
    "network_udp_sock",
    "network_tcp_listen",
    "network_dns",
    "spreading_file",
    "escalate_priv",
    "screenshot",
    "powershell",
    "network_http",
    "win_private_profile"
]

# Iterate through directories to build paths
for root, dirs, files in os.walk(base_directory):
    # Look for directories that match the pattern and append '/json report'
    for dir_name in dirs:
        json_report_path = os.path.join(root, dir_name, 'json report')
        
        # Check if this directory exists
        if os.path.isdir(json_report_path):
            # Iterate through directories inside 'json report' to find 'reports/report.json'
            for sub_root, sub_dirs, sub_files in os.walk(json_report_path):
                for sub_dir in sub_dirs:
                    report_json_path = os.path.join(sub_root, sub_dir, 'reports', 'report.json')
                    #print(report_json_path)
                    # Process each report.json file if it exists
                    if os.path.isfile(report_json_path):
                        with open(report_json_path, 'r') as f:
                            #print(report_json_path)
                            data = json.load(f)
                        
                        # Extract variables
                        virustotal_positives = data['virustotal']['positives'] if data.get('virustotal') else 0
                        virustotal_normalized = len(data['virustotal']['normalized']) if data.get('virustotal') else 0

                        extracted_files = len(data['extracted']) if data.get('extracted') else 0

                        buffer_data = sum(1 for buffer in data['buffer'] if buffer['type'] == 'data') if data.get('buffer') else 0

                        suricata_http = len(data['suricata']['http']) if data.get('suricata') else len(data['network']['http']) if data.get('network') and 'http' in data['network'] else 0
                        suricata_alerts = len(data['suricata']['alerts']) if data.get('suricata') else 0

                        dropped_files = len(data['dropped']) if data.get('dropped') else 0
                        processes = len(data['behavior']['processes']) if data.get('behavior') else 0

                        # Behavior summary extraction
                        behavior_summary = data.get('behavior', {}).get('summary', {})

                        file_created = len(behavior_summary.get('file_created', []))
                        file_deleted = len(behavior_summary.get('file_deleted', []))
                        file_moved = len(behavior_summary.get('file_moved', []))
                        file_written = len(behavior_summary.get('file_written', []))
                        file_copied = len(behavior_summary.get('file_copied', []))
                        file_opened = len(behavior_summary.get('file_opened', []))
                        file_failed = len(behavior_summary.get('file_failed', []))
                        file_read = len(behavior_summary.get('file_read', []))
                        file_recreated = len(behavior_summary.get('file_recreated', []))

                        directory_created = len(behavior_summary.get('directory_created', []))
                        directory_deleted = len(behavior_summary.get('directory_deleted', []))
                        directory_moved = len(behavior_summary.get('directory_moved', []))
                        directory_enumerated = len(behavior_summary.get('directory_enumerated', []))

                        regkey_written = len(behavior_summary.get('regkey_written', []))
                        regkey_opened = len(behavior_summary.get('regkey_opened', []))
                        regkey_deleted = len(behavior_summary.get('regkey_deleted', []))
                        regkey_read = len(behavior_summary.get('regkey_read', []))

                        dll_loaded = len(behavior_summary.get('dll_loaded', []))
                        mutex = len(behavior_summary.get('mutex', []))
                        connects_host = len(behavior_summary.get('connects_host', []))
                        command_line = len(behavior_summary.get('command_line', []))
                        fetches_url = len(behavior_summary.get('fetches_url', []))

                        # YARA Signature and TTP extraction
                        yara_markcount = 0
                        rule_results = {rule: 0 for rule in rules_to_check}

                        for signature in data['signatures']:
                            if signature['name'] == 'file_yara':
                                yara_markcount = signature['markcount']
                                for mark in signature['marks']:
                                    rule_in_mark = mark.get('rule')
                                    if rule_in_mark:
                                        for rule in rules_to_check:
                                            if rule.endswith('*'):
                                                if rule_in_mark.startswith(rule[:-1]):
                                                    rule_results[rule] = 1
                                            elif rule_in_mark == rule:
                                                rule_results[rule] = 1

                        total_ttp_count = sum(len(signature.get('ttp', [])) for signature in data['signatures'])

                        # Other names signature extraction
                        results = {name: 0 for name in names_to_check}
                        for signature in data['signatures']:
                            name = signature['name']
                            if name in results:
                                results[name] = signature['markcount']

                        # Prepare row data for CSV
                        row = [
                            virustotal_positives, virustotal_normalized, extracted_files, buffer_data, 
                            suricata_http, suricata_alerts, dropped_files, processes, 
                            file_created, file_deleted, file_moved, file_written, file_copied, file_opened, 
                            file_failed, file_read, file_recreated, directory_created, directory_deleted, 
                            directory_moved, directory_enumerated, regkey_written, regkey_opened, regkey_deleted, 
                            regkey_read, dll_loaded, mutex, connects_host, command_line, fetches_url, yara_markcount, 
                            total_ttp_count
                        ]

                        # Adding rule results
                        for rule in rules_to_check:
                            row.append(rule_results[rule])

                        # Adding names results
                        for name in names_to_check:
                            row.append(results[name])

                        # Append row to all rows
                        all_rows.append(row)



# Extend columns with rules and names
columns.extend(rules_to_check)
columns.extend(names_to_check)

# Write to CSV

with open(output_csv_path, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(columns)  # Write headers
    writer.writerows(all_rows)  # Write all data rows


print("CSV file has been created successfully.")
