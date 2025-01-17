# Risk & Vulnerability Reporting Engine

# Copyright 2022 Carnegie Mellon University.

# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

# Released under a BSD (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.

# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

# Carnegie Mellon® is registered in the U.S. Patent and Trademark Office by Carnegie Mellon University.

# This Software includes and/or makes use of Third-Party Software each subject to its own license.

# DM22-0744
from django.http import JsonResponse
from django.shortcuts import redirect, render, get_object_or_404
from django.views import generic, View
from django.urls import reverse_lazy, reverse
from django.contrib import messages
from django.core import serializers
from ...forms import UploadedFindingForm, EditUploadedFindingForm
from ...models import (
    AffectedSystem,
    EngagementMeta,
    ImageFinding,
    BaseFinding,
    GeneralFinding,
    SpecificFinding,
    UploadedFinding,
    Mitigation,
    Campaign,
    Payload,
    Severities,
    CIS_CSC,
    KEV,
    Report,
)
from ..utils import (
    get_nist_csf,
    get_cis_csc,
    get_timetable,
)
from django.http import HttpResponse, JsonResponse
from decimal import Decimal
import json
import ipaddress
import os
import shutil
import json


class UploadedFindingUpdateView(generic.edit.UpdateView):
    model = UploadedFinding
    form_class = EditUploadedFindingForm
    template_name = 'ptportal/finding/finding_form.html'

    def get_object(self):
        return get_object_or_404(
            UploadedFinding,
            slug=self.kwargs['slug'],
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        finding = self.get_object()

        context['findings'] = serializers.serialize("json", BaseFinding.objects.all())
        context['severity'] = Severities.objects.all()
        context['kevs'] = serializers.serialize("json", KEV.objects.filter(found=True).order_by('cve_id'))
        context['selected_systems'] = serializers.serialize("json", finding.affected_systems.all())
        context['screenshots'] = ImageFinding.objects.filter(finding=finding)
        context['affected_systems'] = serializers.serialize("json", AffectedSystem.objects.all())
        context['mitigation'] = Mitigation.objects.filter(finding=finding)
        context['report'] = Report.objects.all().first()

        engagement = EngagementMeta.object()
        context["engagement"] = engagement
        context["engagement_exists"] = True if engagement else False

        missing_fields = []
        unchanged_fields = []

        if finding.description == finding.finding.description:
            unchanged_fields.append("Finding Description")

        if finding.remediation == finding.finding.remediation:
            unchanged_fields.append("Finding Remediation")

        if finding.affected_systems.values_list().count() == 0:
            missing_fields.append("Affected Systems")

        if context['screenshots'].values_list().count() == 0:
            missing_fields.append("Screenshot(s)")
        else:
            if finding.screenshot_description == "":
                missing_fields.append("Screenshot Description")
            if context['screenshots'].filter(caption='').values_list().count() > 0:
                missing_fields.append("Screenshot Caption(s)")
                
        context['missing'] = ', '.join(missing_fields)
        context['unchanged'] = ', '.join(unchanged_fields)

        return context

    def post(self, request, *args, **kwargs):
        postData = json.loads(request.POST['data'])
        finding = self.get_object()

        affected_systems_data = json.loads(request.POST['systems'])

        affected_systems = []
        mitigation_list = []
        kevs = []
        screenshots = []

        severity = Severities.objects.filter(severity_name=postData['findingSeverity']).first()

        finding.last_validated = postData['lastValidated']
        finding.description = postData['findingDescription']
        finding.remediation = postData['findingRemediation']
        finding.operator_notes = postData['operatorNotes']
        finding.severity = severity
        finding.assessment_type = postData['assessmentType']
        finding.status = postData['findingStatus']
        finding.screenshot_description = postData['screenshotDescription']
        finding.save()

        for i in affected_systems_data:
            if len(i['name']) == 0 or i['name'] == None or i['name'].isspace():
                continue

            elif AffectedSystem.objects.filter(name=i['name']).exists():
                try:
                    obj = AffectedSystem.objects.get(name=i['name'])
                    affected_systems.append(obj)

                    if Mitigation.objects.filter(finding=finding, system=obj).exists():
                        mit = Mitigation.objects.get(finding=finding, system=obj)
                        mit.mitigation = i['mitigation']
                        mit.mitigation_date = i['mitigation_date'] if i['mitigation_date'] and i['mitigation'] else None
                        mit.save()
                    else:
                        mit = Mitigation.objects.create(
                            system = obj,
                            finding = finding,
                            mitigation = i['mitigation'],
                            mitigation_date = i['mitigation_date'] if i['mitigation_date'] and i['mitigation'] else None
                        )
                    mitigation_list.append(mit)
                except Exception as e:
                    print(e)
                    continue

            else:
                try:
                    system = AffectedSystem.objects.create(
                        name = i['name']
                    )
                    affected_systems.append(system)

                    mit = Mitigation.objects.create(
                        system = system,
                        finding = finding,
                        mitigation = i['mitigation'],
                        mitigation_date = i['mitigation_date'] if i['mitigation_date'] and i['mitigation'] else None
                    )
                    mitigation_list.append(mit)
                except Exception as e:
                    print(e)
                    continue

        deletedMitigation = set(Mitigation.objects.filter(finding=finding)) - set(mitigation_list)

        for deleted in deletedMitigation:
            deleted.delete()

        for i in postData['kevs']:
            try:
                kevs.append(KEV.objects.get(cve_id=i))
            except Exception as e:
                print(e)
                continue

        kev_backup = finding.KEV.all()

        if (len(kev_backup) > 0 and len(kevs) == 0):
            reset = True
        else:
            reset = False

        try:
            finding.KEV.clear()
            finding.KEV.add(*kevs)
        except Exception as e:
            print(e)
            finding.KEV.add(*kev_backup)

        finding.save()

        for index, data in enumerate(postData['screenshots']):
            if data['uuid'] is not None:
                img = ImageFinding.objects.get(uuid=data['uuid'])
                img.order = index + 1
                img.caption = data['caption']
                img.save()
            else:
                filename = "file" + str(data['imgOrder'])
                file = request.FILES[filename]
                try:
                    ext = str(file).split('.')[-1].lower()
                except:
                    ext = ""
                try:
                    img = ImageFinding.objects.create(
                        order = index + 1,
                        caption = data['caption'],
                        file = file,
                        ext = ext,
                        finding = finding
                    )
                except Exception as e:
                    print(e)
            screenshots.append(img)

        deletedScreenshots = set(ImageFinding.objects.filter(finding=finding)) - set(screenshots)

        for deleted in deletedScreenshots:
            deleted.delete()
        
        if reset:
            likelihood = None
        elif len(kevs) > 0:
            likelihood = 100
        else:
            likelihood = finding.likelihood

        finding.likelihood=likelihood
        finding.save()

        duplicate_findings = UploadedFinding.objects.filter(uploaded_finding_name=finding.uploaded_finding_name)

        if duplicate_findings.values_list().count() > 1:
            for i, obj in enumerate(duplicate_findings.order_by('severity', 'assessment_type', 'created_at'), start=1):
                obj.duplicate_finding_order = i
                obj.save()

        return HttpResponse(status=200)


class UploadedFindingCreateView(generic.edit.CreateView):
    model = UploadedFinding
    form_class = UploadedFindingForm
    template_name = 'ptportal/finding/finding_form.html'

    def get_object(self):
        return EngagementMeta.object()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        uploaded_findings = [o.uploaded_finding_name for o in UploadedFinding.objects.all()]

        context['findings'] = serializers.serialize("json", BaseFinding.objects.all().order_by('name'))
        context['uploaded_findings'] = uploaded_findings
        context['severity'] = Severities.objects.all()
        context['kevs'] = serializers.serialize("json", KEV.objects.filter(found=True).order_by('cve_id'))
        context['affected_systems'] = serializers.serialize("json", AffectedSystem.objects.all())

        engagement = EngagementMeta.object()
        context["engagement"] = engagement
        context["engagement_exists"] = True if engagement else False

        return context

    def post(self, request, *args, **kwargs):
        postData = json.loads(request.POST['data'])
        affected_systems_data = json.loads(request.POST['systems'])
        
        affected_systems = []
        kevs = []

        for i in affected_systems_data:
            if len(i['name']) == 0 or i['name'] == None or i['name'].isspace():
                continue

            elif AffectedSystem.objects.filter(name=i['name']).exists():
                try:
                    obj = AffectedSystem.objects.get(name=i['name'])
                    affected_systems.append(obj)
                except Exception as e:
                    print(e)
                    continue

            else:
                try:
                    system = AffectedSystem.objects.create(
                        name = i['name']
                    )
                    affected_systems.append(system)
                except Exception as e:
                    print(e)
                    continue

        for i in postData['kevs']:
            try:
                kevs.append(KEV.objects.get(cve_id=i))
            except Exception as e:
                print(e)
                continue

        base_finding = BaseFinding.objects.filter(pk=postData['selectedFinding']['pk']).first()
        severity = Severities.objects.filter(severity_name=postData['findingSeverity']).first()

        if len(kevs) > 0:
            kev = "True"
            likelihood = 100
        else:
            kev = "False"
            likelihood = None

        try:
            finding = UploadedFinding.objects.create(
                created_by = request.user,
                finding = base_finding,
                NIST_800_53 = base_finding.NIST_800_53,
                NIST_CSF = base_finding.NIST_CSF,
                CIS_CSC = base_finding.CIS_CSC,
                uploaded_finding_name = postData['selectedFinding']['fields']['name'],
                description = postData['findingDescription'],
                remediation = postData['findingRemediation'],
                operator_notes = postData['operatorNotes'],
                severity = severity,
                assessment_type = postData['assessmentType'],
                status = postData['findingStatus'],
                screenshot_description = postData['screenshotDescription'],
                likelihood = likelihood
            )

            duplicate_findings = UploadedFinding.objects.filter(uploaded_finding_name=finding.uploaded_finding_name)

            if duplicate_findings.values_list().count() > 1:
                for i, obj in enumerate(duplicate_findings.order_by('severity', 'assessment_type', 'created_at'), start=1):
                    obj.duplicate_finding_order = i
                    obj.save()
            
        except Exception as e:
            print(e)
            return HttpResponse(status=500)

        for sys in affected_systems_data:
            if len(sys['name']) == 0 or sys['name'] == None or sys['name'].isspace():
                continue

            else:
                try:
                    obj = AffectedSystem.objects.get(name=sys['name'])
                    mit = Mitigation.objects.create(
                        system = obj,
                        finding = finding,
                        mitigation = sys['mitigation'],
                        mitigation_date = sys['mitigation_date'] if sys['mitigation_date'] and sys['mitigation'] else None
                    )
                except Exception as e:
                    print(e)
                    continue
        
        try:
            finding.KEV.add(*kevs)
        except Exception as e:
            print(e)

        for index, data in enumerate(postData['screenshots']):
            filename = "file" + str(data['imgOrder'])
            file = request.FILES[filename]
            try:
                ext = str(file).split('.')[-1].lower()
            except:
                ext = ""
            try:
                img = ImageFinding.objects.create(
                    order = index + 1,
                    caption = data['caption'],
                    file = file,
                    ext = ext,
                    finding = finding
                )
            except Exception as e:
                print(e)
                continue

        return HttpResponse(status=200)


class UploadedFindingDetail(generic.DetailView):
    model = UploadedFinding
    template_name = 'ptportal/finding/finding_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        finding = self.get_object()
        context['screenshots'] = ImageFinding.objects.filter(finding=finding)
        context['report'] = Report.objects.all().first()

        missing_fields = []
        unchanged_fields = []

        if finding.description == finding.finding.description:
            unchanged_fields.append("Finding Description")

        if finding.remediation == finding.finding.remediation:
            unchanged_fields.append("Finding Remediation")

        if finding.affected_systems.values_list().count() == 0:
            missing_fields.append("Affected Systems")

        if context['screenshots'].values_list().count() == 0:
            missing_fields.append("Screenshot(s)")
        else:
            if finding.screenshot_description == "":
                missing_fields.append("Screenshot Description")
            if context['screenshots'].filter(caption='').values_list().count() > 0:
                missing_fields.append("Screenshot Caption(s)")
                
        context['missing'] = ', '.join(missing_fields)
        context['unchanged'] = ', '.join(unchanged_fields)

        return context


class UploadedFindingDelete(generic.edit.DeleteView):
    model = UploadedFinding
    template_name = 'ptportal/finding/finding_confirm_delete.html'
    success_url = reverse_lazy('index')

    def post(self, request, *args, **kwargs):
        finding = self.get_object()
        finding_id = finding.uploaded_finding_id

        screenshot_dir_path = os.path.join("pentestportal", "media", "screenshots")

        try:
            for file in os.listdir(screenshot_dir_path):
                if file.startswith(finding.slug):
                    os.remove(os.path.join(screenshot_dir_path, file))
        except:
            print("Unable to delete finding screenshots from media directory.")

        finding.delete()

        duplicate_findings = UploadedFinding.objects.filter(uploaded_finding_name=finding.uploaded_finding_name)

        if duplicate_findings.values_list().count() > 1:
            for i, obj in enumerate(duplicate_findings.order_by('severity', 'assessment_type', 'created_at'), start=1):
                obj.duplicate_finding_order = i
                obj.save()
        elif duplicate_findings.values_list().count() == 1:
            obj = UploadedFinding.objects.get(uploaded_finding_name=finding.uploaded_finding_name)
            obj.duplicate_finding_order = 0
            obj.save()

        for i in UploadedFinding.objects.all():
            if finding_id < i.uploaded_finding_id:
                try:
                    i.uploaded_finding_id -= 1
                    i.save()
                except:
                    continue

        return redirect(self.success_url)


class KEVs(generic.base.TemplateView):
    model = KEV
    template_name = 'ptportal/finding/kevs.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['json_kevs'] = serializers.serialize("json", KEV.objects.all().order_by('cve_id'))
        context['all_kevs'] = KEV.objects.all().order_by('cve_id')
        context['found_kevs'] = KEV.objects.filter(found=True)

        return context

    def post(self, request, *args, **kwargs):
        postData = json.loads(request.POST['data'])
        kevs = []

        for i in postData['kevs']:
            try:
                obj = KEV.objects.get(cve_id=i)
                obj.found = True
                obj.save()
                kevs.append(obj)
            except Exception as e:
                print(e)
                continue

        deletedKEVs = set(KEV.objects.filter(found=True)) - set(kevs)

        for deleted in deletedKEVs:
            try:
                deleted.found = False
                deleted.save()
            except Exception as e:
                print(e)
                continue

        return HttpResponse(status=200)
