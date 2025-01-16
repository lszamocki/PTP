# Risk & Vulnerability Reporting Engine

# Copyright 2022 Carnegie Mellon University.

# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

# Released under a BSD (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.

# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

# Carnegie Mellon® is registered in the U.S. Patent and Trademark Office by Carnegie Mellon University.

# This Software includes and/or makes use of Third-Party Software each subject to its own license.

# DM22-0744
import contextlib
import datetime
import glob
import os
import socket
import re
import pyzipper
import shutil
import subprocess
import json
from zipfile import ZipFile
from django.views import generic

from os.path import join
from rest_framework.renderers import JSONRenderer

from django.conf import settings
from django.core import serializers
from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404, JsonResponse, HttpResponseServerError
from django.shortcuts import HttpResponse, render

from report_gen.pt_report import generate_ptp_report
from report_gen.pt_kev import generate_kev_report
from report_gen.pt_findings_csv import generate_findings_csv
from report_gen.pt_slide import generate_ptp_slides
from report_gen.pt_tracker import create_tracker
from report_gen.pt_pace import generate_pace_document

from ptportal.serializers import ElectionInfrastructureSerializer, HVASerializer

from ptportal.models import *

from ptportal.views.utils import (
    serializeJSON,
    report_read_csv,
    generateEntryJson,
    generateElectionJson,
    save_chart,
    gen_ptp_filename,
)

from ptp import partial_backup as backup

media_path = settings.MEDIA_ROOT

if settings.DEBUG:
    DOWNLOAD_ZIP = False

def report_findings_counts():
    # Findings Breakdown counts
    findings_breakdown = dict()

    critical = UploadedFinding.critical.all()
    high = UploadedFinding.high.all()
    medium = UploadedFinding.medium.all()
    low = UploadedFinding.low.all()
    informational = UploadedFinding.informational.all()
    
    external = UploadedFinding.external.all()
    internal = UploadedFinding.internal.all()
    phishing = UploadedFinding.phishing.all()

    findings_breakdown['Critical'] = critical
    findings_breakdown['High'] = high
    findings_breakdown['Medium'] = medium
    findings_breakdown['Low'] = low
    findings_breakdown['Info'] = informational

    findings_breakdown['External'] = external
    findings_breakdown['Internal'] = internal
    findings_breakdown['Phishing'] = phishing

    findings_breakdown['External_Critical'] = critical.intersection(external)
    findings_breakdown['External_High'] = high.intersection(external)
    findings_breakdown['External_Medium'] = medium.intersection(external)
    findings_breakdown['External_Low'] = low.intersection(external)
    findings_breakdown['External_Info'] = informational.intersection(external)

    findings_breakdown['Internal_Critical'] = critical.intersection(internal)
    findings_breakdown['Internal_High'] = high.intersection(internal)
    findings_breakdown['Internal_Medium'] = medium.intersection(internal)
    findings_breakdown['Internal_Low'] = low.intersection(internal)
    findings_breakdown['Internal_Info'] = informational.intersection(internal)

    findings_breakdown['Phishing_Critical'] = critical.intersection(phishing)
    findings_breakdown['Phishing_High'] = high.intersection(phishing)
    findings_breakdown['Phishing_Medium'] = medium.intersection(phishing)
    findings_breakdown['Phishing_Low'] = low.intersection(phishing)
    findings_breakdown['Phishing_Info'] = informational.intersection(phishing)
    return findings_breakdown


class Export(generic.base.TemplateView):
    template_name = "ptportal/export.html"

    def get_context_data(self, **kwargs):
        context = {}
        engagement = EngagementMeta.object()
        report = Report.object()
        if engagement:
            context['eng_meta'] = engagement
        if report:
            context['report'] = report

        uploaded_list = UploadedFinding.objects.all().order_by('assessment_type', 'severity', 'uploaded_finding_name')
        cis_csc_objects = CIS_CSC.objects.all().order_by('CIS_ID')

        if report.report_type == "RVA":
            if UploadedFinding.objects.filter(magnitude='').count() > 0 or UploadedFinding.objects.filter(likelihood__isnull=True).count() > 0:
                context['incomplete_risk_score'] = True
            else:
                context['incomplete_risk_score'] = False
        else:
            context['incomplete_risk_score'] = False

        for c in cis_csc_objects:
            ciscsc_findings = c.findings.all()
            finding_ids = []
            for count, u in enumerate(uploaded_list):
                if u.finding in ciscsc_findings:
                    finding_ids.append(count + 1)
            c.finding_ids = ', '.join(str(e) for e in finding_ids)
            c.save()

        context['findings_breakdown'] = report_findings_counts()

        missing_engagement_fields = []

        if EngagementMeta.objects.values_list().count() > 0:

            if engagement.customer_long_name == "":
                missing_engagement_fields.append("Stakeholder Name")
            if engagement.customer_initials == "":
                missing_engagement_fields.append("Stakeholder Abbreviation")
            if engagement.customer_POC_name == "":
                missing_engagement_fields.append("Point of Contact Name")
            if engagement.customer_POC_email == "":
                missing_engagement_fields.append("Point of Contact Email")
            if report.report_type == 'RVA':
                if engagement.customer_location == "":
                    missing_engagement_fields.append("On-Site Testing Address")
            if engagement.customer_state == "":
                missing_engagement_fields.append("State")
            if engagement.customer_sector == "":
                missing_engagement_fields.append("Sector")
            if engagement.customer_ci_type == "":
                missing_engagement_fields.append("Critical Infrastructure Type")
            if engagement.customer_ci_subsector == "":
                missing_engagement_fields.append("Critical Infrastructure Subsector")
            if engagement.team_lead_name == "":
                missing_engagement_fields.append("Team Lead Name")
            if engagement.team_lead_email == "":
                missing_engagement_fields.append("Team Lead Email")

            if report.report_type == 'RVA' or report.report_type == 'RPT':
                if engagement.phishing_domains == "":
                    missing_engagement_fields.append("In Scope Mail Domains for Phishing")

            if report.report_type == 'RVA' or report.report_type == 'FAST':
                if engagement.ext_start_date == None:
                    missing_engagement_fields.append("External Start Date")
                if engagement.ext_end_date == None:
                    missing_engagement_fields.append("External End Date")
                if engagement.ext_scope == "":
                    missing_engagement_fields.append("External In Scope IP Addresses/Domain Names")
                if engagement.ext_excluded_scope == "":
                    missing_engagement_fields.append("External Out of Scope IP Addresses/Domain Names")

            if report.report_type == 'RVA':
                if engagement.int_start_date == None:
                    missing_engagement_fields.append("Internal Start Date")
                if engagement.int_end_date == None:
                    missing_engagement_fields.append("Internal End Date")
                if engagement.int_scope == "":
                    missing_engagement_fields.append("Internal In Scope IP Addresses/Domain Names")
                if engagement.int_excluded_scope == "":
                    missing_engagement_fields.append("Internal Out of Scope IP Addresses/Domain Names")

            if report.report_type == 'RPT':
                if engagement.ext_scope == "":
                    missing_engagement_fields.append("In Scope IP Addresses for Network Penetration Test")
                if engagement.ext_excluded_scope == "":
                    missing_engagement_fields.append("Out of Scope IP Addresses for Network Penetration Test")
                if engagement.web_app_scope == "":
                    missing_engagement_fields.append("In Scope Web Applications")
                if engagement.osinf_scope == "":
                    missing_engagement_fields.append("In Scope Domains for OSINF")

            context['missing_engagement'] = ', '.join(missing_engagement_fields)

        context['payloads'] = Payload.objects.all().order_by('order')
        context['used_solutions'] = SecuritySolution.objects.filter(used=True)

        missing_payload_data = []

        if report.payload_testing_date == None:
            missing_payload_data.append("Payload Testing Date")
        if report.exception == "":
            missing_payload_data.append("Exception")
        if report.browser == "":
            missing_payload_data.append("Browser")

        for p in context['payloads']:
            if p.c2_protocol == "":
                missing_payload_data.append(str(p.order))

        context['missing_payload'] = ', '.join(missing_payload_data)

        context['campaigns'] = Campaign.objects.all().order_by('order')

        missing_campaign_data = []

        if report.phishing_campaign_date == None:
            missing_campaign_data.append("Phishing Campaign Date")

        for c in context['campaigns']:
            if c.emails_sent == None or c.emails_delivered == None or c.total_clicks == None or c.unique_clicks == None or c.time_to_first_click == None or c.length_of_campaign == None or c.campaign_description == "":
                missing_campaign_data.append(str(c.order))

        context['missing_campaign'] = ', '.join(missing_campaign_data)

        context['findings'] = findings = UploadedFinding.objects.all()

        missing_finding_data = []

        for f in context['findings']:
            if f.description == f.finding.description or f.remediation == f.finding.remediation or f.affected_systems.values_list().count() == 0 or ImageFinding.objects.filter(finding=f).values_list().count() == 0:
                missing_finding_data.append(f.uploaded_finding_name)
                continue

            elif ImageFinding.objects.filter(finding=f).values_list().count() > 0:
                if f.screenshot_description == "":
                    missing_finding_data.append(f.uploaded_finding_name)
                    continue
                if ImageFinding.objects.filter(finding=f, caption='').values_list().count() > 0:
                    missing_finding_data.append(f.uploaded_finding_name)
                    continue

        context['missing_finding'] = ', '.join(missing_finding_data)

        missing_narrative_type = []
        missing_narrative_data = []

        ext_narratives = Narrative.objects.filter(assessment_type=1)
        int_narratives = Narrative.objects.filter(assessment_type=2)
        phi_narratives = Narrative.objects.filter(assessment_type=3)

        if ext_narratives.values_list().count() == 0:
            missing_narrative_type.append("External")
        if phi_narratives.values_list().count() == 0:
            missing_narrative_type.append("Phishing")
        if report.report_type == "RVA" and int_narratives.values_list().count() == 0:
            missing_narrative_type.append("Internal")

        context['missing_narrative_type'] = ', '.join(missing_narrative_type)

        for n in ext_narratives:
            steps = NarrativeStep.objects.filter(narrative=n)
            if n.file == "" or n.caption == "" or n.tools.values_list().count() == 0 or n.attack.values_list().count() == 0 or steps.values_list().count() == 0:
                missing_narrative_data.append(n.name + " " + str(n.order))
            else:
                for s in steps:
                    if s.description == "":
                        missing_narrative_data.append(n.name + " " + str(n.order))
                        break
                    elif s.file != "" and s.caption == "":
                        missing_narrative_data.append(n.name + " " + str(n.order))
                        break

        if report.report_type == "RVA":
            for n in int_narratives:
                steps = NarrativeStep.objects.filter(narrative=n)
                if n.file == "" or n.caption == "" or n.tools.values_list().count() == 0 or n.attack.values_list().count() == 0 or steps.values_list().count() == 0:
                    missing_narrative_data.append(n.name + " " + str(n.order))
                else:
                    for s in steps:
                        if s.description == "":
                            missing_narrative_data.append(n.name + " " + str(n.order))
                            break
                        elif s.file != "" and s.caption == "":
                            missing_narrative_data.append(n.name + " " + str(n.order))
                            break

        for n in phi_narratives:
            steps = NarrativeStep.objects.filter(narrative=n)
            if n.file == "" or n.caption == "" or n.tools.values_list().count() == 0 or n.attack.values_list().count() == 0 or steps.values_list().count() == 0:
                missing_narrative_data.append(n.name + " " + str(n.order))
            else:
                for s in steps:
                    if s.description == "":
                        missing_narrative_data.append(n.name + " " + str(n.order))
                        break
                    elif s.file != "" and s.caption == "":
                        missing_narrative_data.append(n.name + " " + str(n.order))
                        break

        context['missing_narrative_data'] = ', '.join(missing_narrative_data)

        missing_services = []

        if PortMappingHost.objects.all().values_list().count() == 0:
            missing_services.append("Port Mapping")
        else:
            for h in PortMappingHost.objects.all():
                if h.ip == "" or h.hostname == "" or h.ports == "" or h.services == "":
                    missing_services.append("Port Mapping")
                    break

        if report.report_type == "RVA":
            if DataExfil.objects.all().values_list().count() == 0:
                missing_services.append("Data Exfiltration")
            else:
                for d in DataExfil.objects.all():
                    if d.protocol == "" or d.datatype == "" or d.date_time == None:
                        missing_services.append("Data Exfiltration")
                        break

            if RansomwareScenarios.objects.all().values_list().count() == 0 or Ransomware.objects.all().values_list().count() == 0:
                missing_services.append("Ransomware")
            else:
                for r in Ransomware.objects.all():
                    if not r.disabled:
                        if r.time_start == None:
                            missing_services.append("Ransomware")
                            break
                    elif r.trigger == "Y" and r.time_end == None:
                        missing_services.append("Ransomware")
                        break

        if report.report_type == "RPT":
            breach_metrics = BreachMetrics.objects.all().first()
            if BreachMetrics.objects.values_list().count() > 0:
                if breach_metrics.emails_identified == None or breach_metrics.emails_identified_tp == None or breach_metrics.creds_identified == None or breach_metrics.creds_identified_unique == None or breach_metrics.creds_validated == None:
                    missing_services.append("OSINF")
            else:
                missing_services.append("OSINF")
            if "OSINF" not in missing_services:
                for e in BreachedEmail.objects.all():
                    if e.email_address == "" or e.breach_info == "":
                        missing_services.append("OSINF")
                        break
                        
        context['missing_services'] = ', '.join(missing_services)

        context['found_kevs'] = KEV.objects.filter(found=True)

        missing_report = False

        if report.report_type == "RVA" or report.report_type == "RPT":
            if report.significant_findings == "" or report.recommendations == "" or report.observed_strengths == "":
                missing_report = True

        if report.report_type == "RVA":
            if report.users_targeted == None or report.external_discovered == None or report.external_scanned == None or report.internal_discovered == None or report.internal_scanned == None or report.password_analysis == "":
                missing_report = True
        else:
            if report.external_discovered == None or report.external_discovered == None:
                missing_report = True

        context['missing_report'] = missing_report

        # NIST_800_53
        context['nist_ac'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='AC'
        ).count()
        context['nist_at'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='AT'
        ).count()
        context['nist_au'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='AU'
        ).count()
        context['nist_ca'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='CA'
        ).count()
        context['nist_cm'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='CM'
        ).count()
        context['nist_cp'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='CP'
        ).count()
        context['nist_ia'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='IA'
        ).count()
        context['nist_ir'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='IR'
        ).count()
        context['nist_ma'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='MA'
        ).count()
        context['nist_mp'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='MP'
        ).count()
        context['nist_pe'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='PE'
        ).count()
        context['nist_pl'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='PL'
        ).count()
        context['nist_pm'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='PM'
        ).count()
        context['nist_ps'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='PS'
        ).count()
        context['nist_pt'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='PT'
        ).count()
        context['nist_ra'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='RA'
        ).count()
        context['nist_sa'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='SA'
        ).count()
        context['nist_sc'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='SC'
        ).count()
        context['nist_si'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='SI'
        ).count()
        context['nist_sr'] = UploadedFinding.objects.filter(
            finding__NIST_800_53__icontains='SR'
        ).count()

        # NIST_CSF
        context['nist_iam'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='ID.AM'
        ).count()
        context['nist_ig'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='ID.GV'
        ).count()
        context['nist_ira'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='ID.RA'
        ).count()
        context['nist_isc'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='ID.SC'
        ).count()
        context['nist_pac'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='PR.AC'
        ).count()
        context['nist_pat'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='PR.AT'
        ).count()
        context['nist_pds'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='PR.DS'
        ).count()
        context['nist_pip'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='PR.IP'
        ).count()
        context['nist_pma'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='PR.MA'
        ).count()
        context['nist_ppt'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='PR.PT'
        ).count()
        context['nist_dae'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='DE.AE'
        ).count()
        context['nist_dcm'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='DE.CM'
        ).count()
        context['nist_ddp'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='DE.DP'
        ).count()
        context['nist_rmi'] = UploadedFinding.objects.filter(
            finding__NIST_CSF__icontains='RS.MI'
        ).count()

        return context

    def post(self, request, *args, **kwargs):
        postData = json.loads(request.body)
        riskChart = bytes(postData['riskChart'], 'utf-8')
        nistSPChart = bytes(postData['nistSPChart'], 'utf-8')
        nistFrameworkChart = bytes(postData['nistFrameworkChart'], 'utf-8')
        save_chart(riskChart, 'riskchart')
        save_chart(nistSPChart, 'nistspchart')
        save_chart(nistFrameworkChart, 'nistframeworkchart')
        return HttpResponse(status=200)


def remove_unnecessary_files(json=True, zip=True):
    # remove all unnecessary .json and .zip files
    if json:
        json_files = glob.glob(os.getcwd() + '/*.json')
        for f in json_files:
            os.remove(f)
    if zip:
        zip_files = glob.glob(os.getcwd() + '/*.zip')
        for f in zip_files:
            os.remove(f)


def export_json(
    data=None,
    zip=False,
    password_protected=True,
    json_file='json_file.json',
    zip_name=None,
    anon_report=False,
):
    engagement_obj = EngagementMeta.objects.all()[:1].get()
    asmt_id = engagement_obj.asmt_id

    if data == 'standard':
        json_file = gen_ptp_filename(prefix=f'VMA{asmt_id}-data', ext='json')
        generateEntryJson(json_file)
    elif data == 'election':
        json_file = gen_ptp_filename(prefix=f'VMA{asmt_id}-election', ext='json')
        generateElectionJson(json_file)
    with open(json_file, 'rb') as fh:
        response = HttpResponse(fh.read(), content_type="application/json, application/octet-stream")
        response['Content-Disposition'] = 'attachment; filename=' + os.path.basename(json_file)

    remove_unnecessary_files()
        
    return response


def generate_EI_json(request):
    return export_json(data='election')


def generate_json(request):
    return export_json(data='standard')


def download_backup(request):
    # reference backup method used in ptp.py CLI
    backup_file = backup(
        in_docker=True, password=EngagementMeta.objects.first().report_password
    )

    # Download backup zip through browser
    content_type = "application/octet-stream"
    if os.path.exists(backup_file):
        with open(backup_file, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type=content_type)
            response[
                'Content-Disposition'
            ] = 'attachment; filename=' + os.path.basename(backup_file)
        remove_unnecessary_files()
        return response

    return render(request, 'ptportal/export.html')


def generate_artifact(artifact_type, anon_report=False):
    base_ctype = "application/vnd.openxmlformats-officedocument."

    report_obj = Report.objects.all()[:1].get()
    engagement_obj = EngagementMeta.objects.all()[:1].get()

    asmt_id = engagement_obj.asmt_id
    cust_initials = engagement_obj.customer_initials

    if report_obj.report_type == "":
        print("Report type is not set.")
        report_type = "RVA"
    else:
        report_type = report_obj.report_type

    report_type_template = report_type.lower()
    json_filename = serializeJSON()
    artifact_name_base = (
        report_type
        + "-"
        + asmt_id
        + "-"
        + cust_initials
        + "-"
        + artifact_type
        + "_Draft-YYYYMMDD"
    )

    template_name_base = "report_gen/templates/" + report_type_template + "-template"

    if artifact_type == "Report":
        content_type = base_ctype + "wordprocessingml.document"
        template_name = template_name_base + '.docx'
        artifact_name = artifact_name_base + '.docx'

        generate_ptp_report(template_name, artifact_name, True, json_filename, settings.MEDIA_ROOT)

    elif artifact_type == "Out-Brief":
        content_type = base_ctype + "presentationml.presentation"
        template_name = template_name_base + '.pptx'
        artifact_name = artifact_name_base + '.pptx'

        generate_ptp_slides(template_name, artifact_name, True, json_filename, settings.MEDIA_ROOT, False)

    elif artifact_type == "Out-Brief-WS":
        content_type = base_ctype + "presentationml.presentation"
        template_name = template_name_base + '-ws' + '.pptx'
        artifact_name = artifact_name_base + '.pptx'

        generate_ptp_slides(template_name, artifact_name, True, json_filename, settings.MEDIA_ROOT, True)

    elif artifact_type == "PACE":
        content_type = base_ctype + "pdf"
        assets = "report_gen/templates/PACE/"
        artifact_name = report_type + "-" + asmt_id + "-" + cust_initials + "-PACE.pdf"

        generate_pace_document(artifact_name, json_filename, assets)

    elif artifact_type == "KEV":
        content_type = base_ctype + "wordprocessingml.document"
        template_name = 'report_gen/templates/KEV-template.docx'
        artifact_name = report_type + "-" + asmt_id + "-" + "Known-Exploited-Vulnerabilities" + '.docx'

        generate_kev_report(template_name, artifact_name, json_filename, settings.MEDIA_ROOT)

    elif artifact_type == "CSV":
        content_type = "text/csv"
        artifact_name = report_type + "-" + asmt_id + "-" + cust_initials + "-" + "Findings" + '.csv'
        generate_findings_csv(artifact_name, json_filename, settings.MEDIA_ROOT)

    elif artifact_type == "Tracker":
        content_type = base_ctype + "spreadsheetml.sheet"
        artifact_name = report_type + "-" + asmt_id + "-" + cust_initials + "-ActivityTracker.xlsx"

        create_tracker(artifact_name, json_filename)

    download_file = artifact_name

    if os.path.exists(download_file):
        with open(download_file, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type=content_type)
            response[
                'Content-Disposition'
            ] = 'attachment; filename=' + os.path.basename(download_file)

        os.remove(download_file)

        with contextlib.suppress(FileNotFoundError):
            os.remove(json_filename)
        return response
    else:
        return HttpResponseServerError()


def generate_report(request):
    return generate_artifact("Report")


def generate_outbrief(request):
    return generate_artifact("Out-Brief")


def generate_outbrief_ws(request):
    return generate_artifact("Out-Brief-WS")


def generate_tracker(request):
    return generate_artifact("Tracker")


def generate_pace(request):
    return generate_artifact("PACE")


def generate_kevs(request):
    return generate_artifact("KEV")

def generate_csv(request):
    return generate_artifact("CSV")

