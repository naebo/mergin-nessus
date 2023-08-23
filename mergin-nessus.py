import os
import sys
import xml.etree.ElementTree as ET

def merge_findings(master_host, new_host):
    """Time to merge! no duplicate hosts pls"""
    master_findings = {ET.tostring(item): item for item in master_host.findall('./ReportItem')}
    for item in new_host.findall('./ReportItem'):
        str_item = ET.tostring(item)
        if str_item not in master_findings:
            master_host.append(item)

def get_or_create_host(master_root, hostname):
    """Checks hosts are new or dupe"""
    for report_host in master_root.findall(".//ReportHost"):
        if report_host.get('name') == hostname:
            return report_host
    new_host = ET.SubElement(master_root.find(".//Report"), 'ReportHost', {'name': hostname})
    return new_host

def rename_report_name(master_root, new_name):
    """New report name (shows as label inside nessus)"""
    report_tag = master_root.find(".//Report")
    if report_tag is not None and 'name' in report_tag.attrib:
        report_tag.attrib['name'] = new_name

def merge_nessus_files(files, report_name):
    """Combining the files..."""
    master_tree = None
    master_root = None

    for file in files:
        tree = ET.parse(file)
        root = tree.getroot()

        if master_tree is None:
            master_tree = tree
            master_root = root
        else:
            for report in root.findall(".//Report"):
                for child in report.findall(".//ReportHost"):
                    hostname = child.get('name')
                    existing_or_new_host = get_or_create_host(master_root, hostname)
                    merge_findings(existing_or_new_host, child)

    # New name who dis
    rename_report_name(master_root, report_name)

    return master_tree

def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <output_file_name.nessus> <new_report_name> <input_folder_or_file1> [<file2> ... <fileN>]")
        return

    output_file = sys.argv[1]
    new_report_name = sys.argv[2]
    input_args = sys.argv[3:]

    if len(input_args) == 1 and os.path.isdir(input_args[0]):
        # A whole folder!?
        input_folder = input_args[0]
        files_to_merge = [os.path.join(input_folder, f) for f in os.listdir(input_folder) if f.endswith('.nessus')]
    else:
        # Just files!?
        files_to_merge = input_args

    combined_tree = merge_nessus_files(files_to_merge, new_report_name)
    combined_tree.write(output_file, encoding='utf-8', xml_declaration=True)
    print(f"Babe, here's ur combined results in {output_file} 💖")

if __name__ == "__main__":
    main()
