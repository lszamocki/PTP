"""
The RVA report generator takes a document template and information
from the RVA pen testing django app database to generate an RVA report
in docx format
"""
# Risk & Vulnerability Assessment Reporting Engine

# Copyright 2022 The Risk & Vulnerability Reporting Engine Contributors, All Rights Reserved.
# (see Contributors.txt for a full list of Contributors)

# SPDX-License-Identifier: BSD-3-Clause

# Please see additional acknowledgments (including references to third party source code, object code, documentation and other files) in the license.txt file or contact permission@sei.cmu.edu for full terms.

# Created, in part, with funding and support from the United States Government. (see Acknowledgments file).

# DM22-1011

import sys
import os.path
import argparse

import report_gen.utilities.assessment_facts as af
import report_gen.utilities.xml_util as xu

from ptportal.models import UploadedFinding, Mitigation

try:
    import csv
except ImportError:
    print("Must have python csv library installed")
    sys.exit(1)


def generate_findings_csv(output, json, media):
    """Generates a PTP report based on the provided json data.

    Args:
        output (string): Name of the file that will be saved and returned.
        json (string): Path to the json file with the assessment data.
        media (string): Path to the media folder that contains the assessment screenshots.
    """
    if not os.path.exists(json):
        print("Invalid json file: ", json)
        sys.exit(1)
    if not os.path.exists(media):
        print("Invalid media path: ", media)
        sys.exit(1)

    # ---- Get data
    # gather meta, ndf, mam stats for charts, tables, etc.
    rva_info = af.load_asmt_info(json)

    with open(output, 'w', newline='') as file:
        writer = csv.writer(file)
        labels = ["Finding Name", "Severity", "Affected System", "Description", "Remediation", "Mitigation Status"]

        writer.writerow(labels)

        findings = UploadedFinding.objects.all().order_by('severity', 'assessment_type', 'uploaded_finding_name', 'created_at')

        for cnt, finding in enumerate(findings):

            if finding.duplicate_finding_order > 0:
                name = finding.uploaded_finding_name + " " + str(finding.duplicate_finding_order)
            else:
                name = finding.uploaded_finding_name
            severity = finding.severity
            description = finding.description
            remediation = finding.remediation

            as_info = af.build_affected_systems_info(rva_info)
            as_info = {k: xu.xsafe(v) for k, v in as_info.items()}
            keys = [affected_system.id for affected_system in finding.affected_systems.all()]
            affected_systems = af.find_affected_systems(as_info, keys)
            affected_systems_list = affected_systems.split(", ")

            for system in affected_systems_list:
                try:
                    mit = Mitigation.objects.get(finding=finding, system__name=system)
                    if mit.mitigation:
                        mitigation = "Mitigated"
                    else:
                        mitigation = "Not Mitigated"
                except Exception as e:
                    print(e)
                    mitigation = "Not Mitigated"
                
                writer.writerow([name, severity, system, description, remediation, mitigation])


def main():
    description = "Generate findings CSV report"
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument(
        "-o",
        "--output_file",
        action="store",
        default="Findings_Report.csv",
        help="Findings CSV report file name",
    )
    parser.add_argument("-j", "--json_file", action="store", required=True)
    parser.add_argument(
        "-m",
        "--media_path",
        action="store",
        default="./",
        help="Location of screenshots, etc.",
    )
    args = parser.parse_args()

    generate_findings_csv(
        args.output_file, args.json_file, args.media_path
    )


if __name__ == '__main__':
    main()
