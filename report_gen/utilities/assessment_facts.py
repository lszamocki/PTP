"""Tempory file to gather local assessment facts from a local json
file and other locations.  This will eventually be retrieved from the
django app

"""
# Risk & Vulnerability Assessment Reporting Engine

# Copyright 2022 The Risk & Vulnerability Reporting Engine Contributors, All Rights Reserved.
# (see Contributors.txt for a full list of Contributors)

# SPDX-License-Identifier: BSD-3-Clause

# Please see additional acknowledgments (including references to third party source code, object code, documentation and other files) in the license.txt file or contact permission@sei.cmu.edu for full terms.

# Created, in part, with funding and support from the United States Government. (see Acknowledgments file).

# DM22-1011

import json
from collections import OrderedDict
from datetime import date

import docx
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

state_to_fema_region = {
    'AK': 'Region 10',
    'AL': 'Region 04',
    'AR': 'Region 06',
    'AS': 'Region 09',
    'AZ': 'Region 09',
    'CA': 'Region 09',
    'CO': 'Region 08',
    'CT': 'Region 01',
    'DC': 'Region 03',
    'DE': 'Region 03',
    'FL': 'Region 04',
    'GA': 'Region 04',
    'GU': 'Region 09',
    'HI': 'Region 09',
    'IA': 'Region 07',
    'ID': 'Region 10',
    'IL': 'Region 05',
    'IN': 'Region 05',
    'KS': 'Region 07',
    'KY': 'Region 04',
    'LA': 'Region 06',
    'MA': 'Region 01',
    'MD': 'Region 03',
    'ME': 'Region 01',
    'MI': 'Region 05',
    'MN': 'Region 05',
    'MO': 'Region 07',
    'MP': 'Region 09',
    'MS': 'Region 04',
    'MT': 'Region 08',
    'NC': 'Region 04',
    'ND': 'Region 08',
    'NE': 'Region 07',
    'NH': 'Region 01',
    'NJ': 'Region 02',
    'NM': 'Region 06',
    'NV': 'Region 09',
    'NY': 'Region 02',
    'OH': 'Region 05',
    'OK': 'Region 06',
    'OR': 'Region 10',
    'PA': 'Region 03',
    'PR': 'Region 02',
    'RI': 'Region 01',
    'SC': 'Region 04',
    'SD': 'Region 08',
    'TN': 'Region 04',
    'TX': 'Region 06',
    'UT': 'Region 08',
    'VA': 'Region 03',
    'VI': 'Region 02',
    'VT': 'Region 01',
    'WA': 'Region 10',
    'WI': 'Region 05',
    'WV': 'Region 03',
    'WY': 'Region 08',
}

# ---- Get the json information
def load_asmt_info(json_file):
    with open(json_file) as f:
        return json.load(f)


def get_region_email(state):
    try:
        fema_region = state_to_fema_region[state]
        region_number = fema_region.split()[-1]
        email = f"CISA.IOD.REGION.R{region_number}_Cyber_Security@cisa.dhs.gov"
    except:
        if state == "<not set: {Customer State}>":
            print("Missing value for customer state.")
        else:
            print("No region found for: " + state)
        email = "<IOD REGION EMAIL ALIAS>"
    return email

def add_hyperlink(paragraph, text, url):
    # Create a new "hyperlink" element
    part = paragraph.part
    r_id = part.relate_to(url, docx.opc.constants.RELATIONSHIP_TYPE.HYPERLINK, is_external=True)
    hyperlink = OxmlElement('w:hyperlink')
    hyperlink.set(qn('r:id'), r_id)

    # Create a new run with the specified text
    new_run = OxmlElement('w:r')

    # Set run properties for styling
    rPr = OxmlElement('w:rPr')
    color = OxmlElement('w:color')
    color.set(qn('w:val'), '0000FF')  # Blue color in hex
    rPr.append(color)

    underline = OxmlElement('w:u')
    underline.set(qn('w:val'), 'single')  # Underline the text
    rPr.append(underline)

    new_run.append(rPr)

    # Create the text element and add it to the run
    text_elem = OxmlElement('w:t')
    text_elem.text = text
    new_run.append(text_elem)

    # Append the run to the hyperlink
    hyperlink.append(new_run)

    # Append the hyperlink to the paragraph
    paragraph._p.append(hyperlink)

def get_db_info(rva_db, db_loc, key, allow_empty=False):
    """This function is used to get values from elements that have a
    single model, such as `report'
    Using `allow_empty', the user will receieve an empty string
    instead of `<not set:...>' if the key is not set. The user can
    test for empty string and change behavior.
    """
    # print(db_loc)

    db_path = db_loc.split('.')

    found_ele = None
    for ele in rva_db:
        if ele["model"] == 'ptportal.' + db_path[0]:
            found_ele = ele
            break

    field = found_ele
    try:
        for j in db_path[1:]:
            if type(field[j]) == list:
                if len(field[j]) > 0:
                    if type(field[j][0]) == dict:
                        all_dict_values = []
                        for x in field[j]:
                            all_dict_values.extend(list(x.values()))
                        field[j] = all_dict_values
                    else:  # make sure it is a string
                        field[j] = [str(s) for s in field[j]]
            field = field[j]
    except:
        field = ""

    if field == "":
        if allow_empty:
            return ""
        else:
            field = "<not set: " + key + ">"
    return field


# map tags in template to database locations
tag_db_map = {
    "{Stakeholder Name}": "engagementmeta.fields.customer_long_name",
    "{Stakeholder Initials}": "engagementmeta.fields.customer_initials",
    "{POC Name}": "engagementmeta.fields.customer_POC_name",
    "{POC Email}": "engagementmeta.fields.customer_POC_email",
    "{ASMT ID}": "engagementmeta.fields.asmt_id",
    "{Team Lead Name}": "engagementmeta.fields.team_lead_name",
    "{Team Lead Email}": "engagementmeta.fields.team_lead_email",
    "{External Dates}": "engagementmeta.fields.ext_start_date",
    "{Stakeholder Location}": "engagementmeta.fields.customer_location",
    "{Customer State}": "engagementmeta.fields.customer_state",
    "{Short business level external scope – tech scope is in appendix.}": "report.fields.scanned_scope_ext",
    "{Internal Dates}": "engagementmeta.fields.int_start_date",
    "{Traffic Light}": "engagementmeta.fields.traffic_light_protocol",
    "{total number of emails found}": "report.fields.emails_identified",
    "{total number of breached emails found}": "report.fields.emails_breached",
    "{number of credentials identified}": "report.fields.credentials_identified",
    "{number of credentials validated}": "report.fields.credentials_validated",
    "{Calculate Percent of Breached Emails}": "report.fields.email_percentage",
    "[Enter Assessment Title]": "report.fields.report_title",
}


def set_draft(db):
    """Update the report date string to include the word DRAFT"""
    for ele in db:
        if ele["model"] == "ptportal.report":
            break

    rdate = date.today().strftime("%Y-%m-%d")
    ele["fields"]["report_date"] = "DRAFT - " + rdate


# ---- NIST Control information retrieval

nist80053 = OrderedDict(
    [("AC", 0), ("AT", 0), ("CM", 0), ("IA", 0), ("RA", 0), ("SC", 0), ("SI", 0)]
)

nistCSF = OrderedDict(
    [
        ("ID.AM", 0),
        ("ID.GV", 0),
        ("ID.RA", 0),
        ("PR.AC", 0),
        ("PR.AT", 0),
        ("PR.DS", 0),
        ("PR.IP", 0),
        ("PR.PT", 0),
    ]
)


def set_title(db):
    """The TOC uses standard paragraph tags to set the title. So this sets
    the report_title in the json map. It could eventually be replaced
    with the django model and this function will be obsoleted.
    """

    # build the title
    emeta = get_db_info(db, "engagementmeta.fields", "keyNA", allow_empty=True)
    rep = get_db_info(db, "report.fields", "keyNA")

    if emeta != "":
        cust_name = emeta["customer_long_name"]
        asmt_id = emeta["asmt_id"]
    else:
        cust_name = "<not set: {CUSTOMER NAME}>"
        asmt_id = "<not set: {ASMT ID}>"

    report_type = rep["report_type"]

    if report_type == "RVA":
        title = "Risk and Vulnerability Assessment Report (Draft)"
    else:
        title = "Report (Draft)"

    subtitle = "RV" + asmt_id + " - " + cust_name

    #title = report_type + " prepared for " + cust_name

    # set the title
    rep["report_title"] = title
    rep["report_subtitle"] = subtitle


def clean_nist_vals(lst, numchars):
    """
    lst -- a list of NIST controls
    numchars -- the number of chars returning only the control
                family part of the string
    """
    vals = lst.split(',')
    vals = [x.strip() for x in vals]
    vals = [x[0:numchars] for x in vals]
    return vals


def model_gen(db, model):
    """Walks the rva data dump looking for a given `model'"""
    for ele in db:
        if ele["model"] == model:
            yield ele


def build_screenshot_info(db):
    """Generate a list of all screenshot entries in the rva data dump"""
    sshots = []
    for ele in model_gen(db, "ptportal.imagefinding"):
        sshots.append(ele)
    return sshots


def build_narrative_info(db):
    """Generate a list of all screenshot entries in the rva data dump"""
    steps = []
    for ele in model_gen(db, "ptportal.narrativestep"):
        steps.append(ele)
    return steps


def find_screenshots(ss_list, fkey):
    """Walk through list of screenshot elements and return a list of
    screenshot elements associated with the finding's key `fkey'
    """
    ss_fkey = []
    for ss in ss_list:
        ssf = ss['fields']
        if ssf["finding"] == fkey:
            ss_fkey.append(ss)
    return ss_fkey


def find_steps(s_list, nkey):
    """Walk through list of steps and return a list of
    elements associated with the narrative's key `nkey'
    """
    s_nkey = []
    for s in s_list:
        sf = s['fields']
        if sf["narrative"] == nkey:
            s_nkey.append(s)
    return s_nkey


def build_affected_systems_info(db):
    """Generate a dictionary of all affected systems"""
    asys = {}
    for ele in model_gen(db, "ptportal.affectedsystem"):
        asys_name = ele['fields']['name']
        pk = ele['pk']
        asys[pk] = asys_name
    return asys


def find_affected_systems(as_info, keys):
    """Generate a concatenated string of affected systems based on passed in keys"""
    asys = []
    for i in keys:
        if i in as_info:
            asys.append(as_info[i])
    return ', '.join(asys)


def get_nist_control_data(ndf_data):
    csf_count = 0

    for finding in model_gen(ndf_data, "ptportal.uploadedfinding"):
        ele = finding["fields"]

        vals = clean_nist_vals(ele["finding__NIST_800_53"], 2)
        for v in vals:
            try:
                nist80053[v] += 1
            except:
                print("Untracked nist 800.53 key", v)

        vals = clean_nist_vals(ele["finding__NIST_CSF"], 5)
        for v in vals:
            csf_count += 1
            try:
                nistCSF[v] += 1
            except:
                print("Untracked nist CSF key", v)

    # update nistCSF as percentage
    for k, v in nistCSF.items():
        try:
            nistCSF[k] = float(v) / float(csf_count)
        except:
            print("no CSF elements found")


if __name__ == '__main__':
    import sys

    rva_info = load_asmt_info(sys.argv[1])  # json file

    get_nist_control_data(rva_info)

    for k, v in nist80053.items():
        print(k, v)

    print("-" * 20)

    for k, v in nistCSF.items():
        print(k, v)
