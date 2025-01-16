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
import os, sys
import re
import subprocess
import ipaddress
from os.path import join
from django.core.management import call_command
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.forms.widgets import SelectDateWidget
from django.http import Http404, JsonResponse
from django.shortcuts import HttpResponse, render, redirect
from django.views import generic
from .utils import serializeJSON, report_read_csv, generateEntryJson, save_chart
from axes.attempts import get_user_attempts
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.signals import user_login_failed
from ..forms import RegistrationForm
from ..models import *
import base64
import json

from django.http import FileResponse
from rest_framework.renderers import JSONRenderer
from django.core.serializers import serialize
from django.core import serializers

from ptportal.serializers import ElectionInfrastructureSerializer

from django.conf import settings
from builtins import int

media_path = settings.MEDIA_ROOT
import shutil
from zipfile import ZipFile


class IndexView(generic.ListView):
    """
    Display dashboard homepage

    ** Context **
        UploadedFinding

    ** Template **
        :template: `ptportal/index.html`
    """

    model = UploadedFinding
    template_name = 'ptportal/index.html'

    def get_context_data(self, **kwargs):
        if EngagementMeta.object():
            engagement_present = True
        else:
            engagement_present = False

        # Call the base implementation first to get a context
        context = super().get_context_data(**kwargs)
        findings = UploadedFinding.objects.all()
        # Add in a QuerySet of all the uploaded files
        context['engagement_present'] = engagement_present
        context['total_critical'] = UploadedFinding.critical.count()
        context['total_high'] = UploadedFinding.high.count()
        context['total_medium'] = UploadedFinding.medium.count()
        context['total_low'] = UploadedFinding.low.count()
        context['total_info'] = UploadedFinding.informational.count()
        context['total_findings'] = UploadedFinding.objects.all().count()
        context['total_payloads'] = Payload.objects.all().count()
        context['total_campaigns'] = Campaign.objects.all().count()
        context['total_port_mappings'] = PortMappingHost.objects.all().count()
        context['total_data_exfil'] = DataExfil.objects.all().count()
        context['total_ransomware'] = Ransomware.objects.all().count()
        context['total_narratives'] = Narrative.objects.all().count()
        context['total_osinf_emails'] = BreachedEmail.objects.all().count()
        context['total_osinf_metrics'] = BreachMetrics.objects.all().count()
        context['total_kevs'] = KEV.objects.filter(found=True).count()
        context['report'] = Report.objects.all().first()
        context['used_solutions'] = SecuritySolution.objects.filter(used=True)

        unique_clicks = 0
        emails_delivered = 0
        total_click_rate = 0

        if Campaign.objects.all().count() > 0:
            for i in Campaign.objects.all():
                unique_clicks += i.unique_clicks
                emails_delivered += i.emails_delivered

            temp = (unique_clicks / emails_delivered) * 100
            total_click_rate = round(temp)

        context['click_rate'] = total_click_rate

        mitigated_score = 0
        total_score = 0

        if UploadedFinding.objects.all().count() > 0:
            for i in UploadedFinding.objects.all():
                total_score += i.risk_score
                mitigated_score += i.mitigated_risk_score

        context['total_risk_score'] = total_score
        context['mitigated_risk_score'] = mitigated_score

        warnings = []
        missing_magnitude = []
        missing_likelihood = []
        duplicate_findings = {}

        for f in findings:

            if f.magnitude == "":
                missing_magnitude.append(f.uploaded_finding_name)

            if f.likelihood == None:
                missing_likelihood.append(f.uploaded_finding_name)

            if f.description == f.finding.description:
                warnings.append(f.uploaded_finding_name)
                continue

            if f.remediation == f.finding.remediation:
                warnings.append(f.uploaded_finding_name)
                continue

            if f.affected_systems.values_list().count() == 0:
                warnings.append(f.uploaded_finding_name)
                continue

            if ImageFinding.objects.filter(finding=f).values_list().count() == 0:
                warnings.append(f.uploaded_finding_name)
                continue

            else:
                if f.screenshot_description == "":
                    warnings.append(f.uploaded_finding_name)
                    continue
                if ImageFinding.objects.filter(finding=f, caption='').values_list().count() > 0:
                    warnings.append(f.uploaded_finding_name)
                    continue

        context['warnings'] = warnings
        context['missing_magnitude'] = ', '.join(missing_magnitude)
        context['missing_likelihood'] = ', '.join(missing_likelihood)

        missing_campaign_results = []
        missing_campaign_descriptions = []

        for c in Campaign.objects.all():
            if c.emails_sent == None or c.emails_delivered == None or c.total_clicks == None or c.unique_clicks == None or c.time_to_first_click == None or c.length_of_campaign == None:
                missing_campaign_results.append(str(c.order))
            if c.campaign_description == "":
                missing_campaign_descriptions.append(str(c.order))

        context['missing_campaign_results'] = ', '.join(missing_campaign_results)
        context['missing_campaign_descriptions'] = ', '.join(missing_campaign_descriptions)

        missing_protocols = []

        for p in Payload.objects.all():
            if p.c2_protocol == "":
                missing_protocols.append(str(p.order))

        context['missing_protocols'] = ', '.join(missing_protocols)

        return context

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.order_by('severity', 'assessment_type', 'uploaded_finding_name', 'created_at')


def signup(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)

        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(
                username=username, password=raw_password, request=request
            )
            warn = "Access to the created account is pending administrator approval."
            messages.warning(request, warn)

            # Notify Admin Users
            #notify.send(
            #    User.objects.filter(username=username).first(),
            #    recipient=User.objects.filter(is_admin=True, is_active=True),
            #    verb="User '" + username + "' Needs Permissions",
            #)
            return redirect('index')
        else:
            key = list(form.errors.keys())[0]
            error = form.errors.as_data().get(key)[0].message
            if "exists" in error:
                error = "An account with this username already exists."
            messages.error(request, error)
            return redirect('signup')
    else:
        form = RegistrationForm()
    return render(request, 'ptportal/signup.html', {'form': form})


def readSenderNotifications(request):
    if request.method == 'GET':
        actor_user = request.GET.get("sender")

        if actor_user:  # Mark all notifications from sender as read
            Notification.objects.filter(actor_object_id=actor_user).mark_all_as_read()

    return


def user_login(request):
    if request.method == 'POST':
        form = AuthenticationForm(request.POST)
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password, request=request)

        if user is not None:
            if user.is_active:
                login(request, user)
                if EngagementMeta.object():
                    return redirect('index')
                # if engagement data does not exist redirect to
                else:
                    return redirect('engagement_create')

        else:
            user_login_failed.send(
                sender=User, request=request, credentials={'username': username}
            )

            failed_attempts = 0
            login_attempts = get_user_attempts(request)

            for attempt in login_attempts:
                failed_attempts = attempt.failures_since_start

            try:
                check_user = User.objects.get(username=username)
            except:
                check_user = None

            if check_user is not None and check_user.is_active == False:
                messages.warning(
                    request, "This account is pending administrator approval."
                )

            elif failed_attempts >= settings.AXES_FAILURE_LIMIT:
                messages.error(
                    request,
                    "Your account has been locked. \n"
                    + "Please contact your \n"
                    + "administrator for more information.",
                )
            else:
                messages.error(
                    request, "Your login is invalid. Please \n" + "try again."
                )
            return redirect('login')
    else:
        form = AuthenticationForm()
    return render(request, 'ptportal/login.html', {'form': form})


def logout_view(request):
    logout(request)
    return redirect('login')


def custom_page_not_found(request, exception, template_name='404.html'):
    return render(request, 'ptportal/errors/404.html', status=404)


def custom_server_error(request, template_name='500.html'):
    return render(request, 'ptportal/errors/500.html', status=500)


def custom_permission_denied(request, exception, template_name='403.html'):
    return render(request, 'ptportal/errors/403.html', status=403)


def custom_bad_request(request, exception, template_name='400.html'):
    return render(request, 'ptportal/errors/400.html', status=400)
