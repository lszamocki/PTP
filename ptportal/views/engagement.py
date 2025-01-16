# Risk & Vulnerability Reporting Engine

# Copyright 2022 Carnegie Mellon University.

# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

# Released under a BSD (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.

# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

# Carnegie Mellon® is registered in the U.S. Patent and Trademark Office by Carnegie Mellon University.

# This Software includes and/or makes use of Third-Party Software each subject to its own license.

# DM22-0744
import datetime, json

from django import forms
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse_lazy, reverse
from django.utils import timezone
from django.views import generic
from django.forms.models import modelformset_factory

from ptportal.forms import (
    EngagementForm,
    HVATargetForm,
    HVATargetFormSet0,
    HVATargetFormSet1,
)

from ptportal.models import (
    EngagementMeta,
    HVAData,
    HVATarget,
    Report,
)


def engagement_redirect(request):
    if EngagementMeta.object():
        return redirect('engagement_detail')
    else:
        return redirect('engagement_create')


class EngagementCreate(generic.edit.CreateView):
    model = EngagementMeta
    form_class = EngagementForm
    template_name = 'ptportal/engagement/engagement_meta_form.html'

    def get_object(self):
        return EngagementMeta.object()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['report'] = Report.object()

        if context['report'].report_type == 'HVA':
            context['hvas'] = HVATarget.objects.all()

        return context

    def get(self, *args, **kwargs):
        if EngagementMeta.objects.all().count() > 0:
            return redirect(reverse('engagement_update'))
        else:
            return super(EngagementCreate, self).get(*args, **kwargs)

    def post(self, request, *args, **kwargs):

        postData = json.loads(request.body)
        report = Report.object()

        engageForm = EngagementForm(postData)

        if engageForm.is_valid():
            engageForm.save()
        else:
            return HttpResponse(status=400, reason=engageForm.errors)

        newHVA = []
        if report.report_type == 'HVA':
            for hva in postData['hvas']:
                try:
                    obj = HVATarget(**hva)
                    obj.full_clean()
                    newHVA.append(obj)
                except ValidationError as e:
                    print(e)
                    return HttpResponse(status=400)

            for hva in newHVA:
                hva.save()

        return super().post(self, request, *args, **kwargs)


class EngagementUpdate(generic.edit.UpdateView):
    model = EngagementMeta
    form_class = EngagementForm
    context_object_name = 'post'
    template_name = 'ptportal/engagement/engagement_meta_form.html'

    def get_object(self):
        return EngagementMeta.object()

    def get_form_kwargs(self):
        """Return the keyword arguments for instantiating the form."""
        kwargs = super().get_form_kwargs()
        if hasattr(self, 'object'):
            kwargs.update({'instance': self.object})
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['report'] = Report.object()
        engagement = EngagementMeta.object()

        if context['report'].report_type == 'HVA':
            context['hvas'] = HVATarget.objects.all()

        missing_fields = []

        if engagement.customer_long_name == "":
            missing_fields.append("Stakeholder Name")
        if engagement.customer_initials == "":
            missing_fields.append("Stakeholder Abbreviation")
        if engagement.customer_POC_name == "":
            missing_fields.append("Point of Contact Name")
        if engagement.customer_POC_email == "":
            missing_fields.append("Point of Contact Email")
        if context['report'].report_type == 'RVA':
            if engagement.customer_location == "":
                missing_fields.append("On-Site Testing Address")
        if engagement.customer_state == "":
            missing_fields.append("State")
        if engagement.customer_sector == "":
            missing_fields.append("Sector")
        if engagement.customer_ci_type == "":
            missing_fields.append("Critical Infrastructure Type")
        if engagement.customer_ci_subsector == "":
            missing_fields.append("Critical Infrastructure Subsector")
        if engagement.team_lead_name == "":
            missing_fields.append("Team Lead Name")
        if engagement.team_lead_email == "":
            missing_fields.append("Team Lead Email")

        if context['report'].report_type == 'RVA' or context['report'].report_type == 'RPT':
            if engagement.phishing_domains == "":
                missing_fields.append("In Scope Mail Domains for Phishing")

        if context['report'].report_type == 'RVA' or context['report'].report_type == 'FAST':
            if engagement.ext_start_date == None:
                missing_fields.append("External Start Date")
            if engagement.ext_end_date == None:
                missing_fields.append("External End Date")
            if engagement.ext_scope == "":
                missing_fields.append("External In Scope IP Addresses/Domain Names")
            if engagement.ext_excluded_scope == "":
                missing_fields.append("External Out of Scope IP Addresses/Domain Names")

        if context['report'].report_type == 'RVA':
            if engagement.int_start_date == None:
                missing_fields.append("Internal Start Date")
            if engagement.int_end_date == None:
                missing_fields.append("Internal End Date")
            if engagement.int_scope == "":
                missing_fields.append("Internal In Scope IP Addresses/Domain Names")
            if engagement.int_excluded_scope == "":
                missing_fields.append("Internal Out of Scope IP Addresses/Domain Names")

        if context['report'].report_type == 'RPT':
            if engagement.ext_scope == "":
                missing_fields.append("In Scope IP Addresses for Network Penetration Test")
            if engagement.ext_excluded_scope == "":
                missing_fields.append("Out of Scope IP Addresses for Network Penetration Test")
            if engagement.web_app_scope == "":
                missing_fields.append("In Scope Web Applications")
            if engagement.osinf_scope == "":
                missing_fields.append("In Scope Domains for OSINF")

        context['missing'] = ', '.join(missing_fields)

        return context

    def post(self, request, *args, **kwargs):
        postData = json.loads(request.body)
        report = Report.object()
        
        if postData['traffic_light_protocol'] == 'None':
            postData['traffic_light_protocol'] = None

        engageForm = EngagementForm(postData, instance=EngagementMeta.objects.get(id=1))
        if engageForm.is_valid():
            engageForm.save()
        else:
            print(engageForm.errors)
            return HttpResponse(status=400, reason=engageForm.errors)

        newHVA = []
        if report.report_type == 'HVA':
            for hva in postData['hvas']:
                try:
                    obj = HVATarget(**hva)
                    obj.full_clean()
                    newHVA.append(obj)
                except ValidationError as e:
                    print(e)
                    return HttpResponse(status=400, reason=e)

            HVATarget.objects.all().delete()
            for hva in newHVA:
                hva.save()

        return super().post(self, request, *args, **kwargs)


class EngagementDelete(generic.edit.DeleteView):
    model = EngagementMeta
    template_name = 'ptportal/engagement/engagement_meta_confirm_delete.html'
    success_url = reverse_lazy('index')

    def get_object(self):
        return EngagementMeta.object()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['report'] = Report.object()
        if context['report'].report_type == 'HVA':
            context['hvas'] = HVATarget.objects.all()
        return context


class EngagementDetail(generic.DetailView):
    model = EngagementMeta
    template_name = 'ptportal/engagement/engagement_meta_detail.html'

    def get_object(self):
        return EngagementMeta.object()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['report'] = Report.object()
        engagement = EngagementMeta.object()
        if context['report'].report_type == 'HVA':
            context['hvas'] = HVATarget.objects.all()

        missing_fields = []

        if engagement.customer_long_name == "":
            missing_fields.append("Stakeholder Name")
        if engagement.customer_initials == "":
            missing_fields.append("Stakeholder Abbreviation")
        if engagement.customer_POC_name == "":
            missing_fields.append("Point of Contact Name")
        if engagement.customer_POC_email == "":
            missing_fields.append("Point of Contact Email")
        if context['report'].report_type == 'RVA':
            if engagement.customer_location == "":
                missing_fields.append("On-Site Testing Address")
        if engagement.customer_state == "":
            missing_fields.append("State")
        if engagement.customer_sector == "":
            missing_fields.append("Sector")
        if engagement.customer_ci_type == "":
            missing_fields.append("Critical Infrastructure Type")
        if engagement.customer_ci_subsector == "":
            missing_fields.append("Critical Infrastructure Subsector")
        if engagement.team_lead_name == "":
            missing_fields.append("Team Lead Name")
        if engagement.team_lead_email == "":
            missing_fields.append("Team Lead Email")

        if context['report'].report_type == 'RVA' or context['report'].report_type == 'RPT':
            if engagement.phishing_domains == "":
                missing_fields.append("In Scope Mail Domains for Phishing")

        if context['report'].report_type == 'RVA' or context['report'].report_type == 'FAST':
            if engagement.ext_start_date == None:
                missing_fields.append("External Start Date")
            if engagement.ext_end_date == None:
                missing_fields.append("External End Date")
            if engagement.ext_scope == "":
                missing_fields.append("External In Scope IP Addresses/Domain Names")
            if engagement.ext_excluded_scope == "":
                missing_fields.append("External Out of Scope IP Addresses/Domain Names")

        if context['report'].report_type == 'RVA':
            if engagement.int_start_date == None:
                missing_fields.append("Internal Start Date")
            if engagement.int_end_date == None:
                missing_fields.append("Internal End Date")
            if engagement.int_scope == "":
                missing_fields.append("Internal In Scope IP Addresses/Domain Names")
            if engagement.int_excluded_scope == "":
                missing_fields.append("Internal Out of Scope IP Addresses/Domain Names")

        if context['report'].report_type == 'RPT':
            if engagement.ext_scope == "":
                missing_fields.append("In Scope IP Addresses for Network Penetration Test")
            if engagement.ext_excluded_scope == "":
                missing_fields.append("Out of Scope IP Addresses for Network Penetration Test")
            if engagement.web_app_scope == "":
                missing_fields.append("In Scope Web Applications")
            if engagement.osinf_scope == "":
                missing_fields.append("In Scope Domains for OSINF")

        context['missing'] = ', '.join(missing_fields)
        
        return context
