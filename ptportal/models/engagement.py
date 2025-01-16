# Risk & Vulnerability Assessment Reporting Engine

# Copyright 2022 The Risk & Vulnerability Reporting Engine Contributors, All Rights Reserved.
# (see Contributors.txt for a full list of Contributors)

# SPDX-License-Identifier: BSD-3-Clause

# Please see additional acknowledgments (including references to third party source code, object code, documentation and other files) in the license.txt file or contact permission@sei.cmu.edu for full terms.

# Created, in part, with funding and support from the United States Government. (see Acknowledgments file).

# DM22-1011

import datetime

from django.core.validators import (
    EmailValidator,
    MaxValueValidator,
    MinValueValidator,
    MinLengthValidator,
    RegexValidator,
)

from django.db import models
from django.db.models import signals
from django.dispatch import receiver
from django.urls import reverse
from django.utils import timezone

from . import abstract_models
from . import findings
from . import report


def current_year():
    return datetime.date.today().year


def max_value_current_year():
    return MaxValueValidator(current_year() + 1)


STATUS_CHOICES = (
    ('Canceled', 'Canceled'),
    ('Completed', 'Completed'),
    ('In Progress', 'In Progress'),
    ('Not Started', 'Not Started'),
    ('On Hold', 'On Hold'),
)


class HVATarget(abstract_models.TimeStampedModel):
    name = models.CharField(
        max_length=200,
        blank=True,
        verbose_name="HVA Name",
        help_text='Common Name of High Value Asset',
    )
    address = models.CharField(
        max_length=200,
        blank=True,
        verbose_name="HVA Address",
        help_text="Either a Hostname, FQDN, or IP Address",
    )
    status = models.CharField(
        max_length=255,
        blank=False,
        verbose_name='HVA Assessment Status',
        choices=STATUS_CHOICES,
        default='Not Started',
        help_text='Indicates the assessment status of the HVA',
    )

    # add system field to link to system
    class Meta:
        verbose_name_plural = 'HVA Targets'
        verbose_name = 'HVA Target'
        ordering = ['name']

    def __str__(self):
        return self.name


class EngagementMeta(abstract_models.TimeStampedModel):
    TLP_CHOICES = (
        ('Clear', 'Clear'),
        ('Amber', 'Amber'), 
        ('Amber+Strict', 'Amber+Strict'),
        ('Red', 'Red'),
    )

    SECTOR_CHOICES = (
        ('Federal', 'Federal'),
        ('State', 'State'),
        ('Local', 'Local'),
        ('Tribal', 'Tribal'),
        ('Territorial', 'Territorial'),
        ('Private', 'Private'),
        ('Other', 'Other'),
    )

    CI_TYPE_CHOICES = (
        ('Chemical', 'Chemical'),
        ('Commercial Facilities', 'Commercial Facilities'),
        ('Communications', 'Communications'),
        ('Critical Manufacturing', 'Critical Manufacturing'),
        ('Dams', 'Dams'),
        ('Defense Industrial Base', 'Defense Industrial Base'),
        ('Emergency Services', 'Emergency Services'),
        ('Energy', 'Energy'),
        ('Financial Services', 'Financial Services'),
        ('Food and Agriculture', 'Food and Agriculture'),
        ('Government Facilities', 'Government Facilities'),
        ('Healthcare and Public Health', 'Healthcare and Public Health'),
        ('Identifying Critical Infrastructure During COVID-19', 'Identifying Critical Infrastructure During COVID-19'),
        ('Information Technology', 'Information Technology'),
        ('Nuclear Reactors, Materials, and Waste', 'Nuclear Reactors, Materials, and Waste'),
        ('Sector-Specific Agencies', 'Sector-Specific Agencies'),
        ('Transportation Systems', 'Transportation Systems'),
        ('Water and Wastewater Systems', 'Water and Wastewater Systems'),
    )

    CI_SUBSECTOR_CHOICES = (
        ('Entertainment and Media', 'Entertainment and Media'),
        ('Gaming', 'Gaming'),
        ('Lodging', 'Lodging'),
        ('Outdoor Events', 'Outdoor Events'),
        ('Public Assembly', 'Public Assembly'),
        ('Real Estate', 'Real Estate'),
        ('Retail', 'Retail'),
        ('Sports Leagues', 'Sports Leagues'),
        ('Electricity', 'Electricity'),
        ('Oil and Natural Gas', 'Oil and Natural Gas'),
        ('Education Facilities', 'Education Facilities'),
        ('Election Infrastructure', 'Election Infrastructure'),
        ('National Monuments and Icons', 'National Monuments and Icons'),
        ('Aviation', 'Aviation'),
        ('Freight Rail', 'Freight Rail'),
        ('Highway and Motor Carrier', 'Highway and Motor Carrier'),
        ('Maritime', 'Maritime'),
        ('Mass Transit and Passenger Rail', 'Mass Transit and Passenger Rail'),
        ('Pipeline', 'Pipeline'),
        ('Postal and Shipping', 'Postal and Shipping'),
        ('N/A', 'N/A'),
    )

    STATE_CHOICES = (
        ('AK', 'Alaska'),
        ('AL', 'Alabama'),
        ('AR', 'Arkansas'),
        ('AS', 'American Samoa'),
        ('AZ', 'Arizona'),
        ('CA', 'California'),
        ('CO', 'Colorado'),
        ('CT', 'Connecticut'),
        ('DC', 'District of Columbia'),
        ('DE', 'Delaware'),
        ('FL', 'Florida'),
        ('GA', 'Georgia'),
        ('GU', 'Guam'),
        ('HI', 'Hawaii'),
        ('IA', 'Iowa'),
        ('ID', 'Idaho'),
        ('IL', 'Illinois'),
        ('IN', 'Indiana'),
        ('KS', 'Kansas'),
        ('KY', 'Kentucky'),
        ('LA', 'Louisiana'),
        ('MA', 'Massachusetts'),
        ('MD', 'Maryland'),
        ('ME', 'Maine'),
        ('MI', 'Michigan'),
        ('MN', 'Minnesota'),
        ('MO', 'Missouri'),
        ('MP', 'Northern Mariana Islands'),
        ('MS', 'Mississippi'),
        ('MT', 'Montana'),
        ('NC', 'North Carolina'),
        ('ND', 'North Dakota'),
        ('NE', 'Nebraska'),
        ('NH', 'New Hampshire'),
        ('NJ', 'New Jersey'),
        ('NM', 'New Mexico'),
        ('NV', 'Nevada'),
        ('NY', 'New York'),
        ('OH', 'Ohio'),
        ('OK', 'Oklahoma'),
        ('OR', 'Oregon'),
        ('PA', 'Pennsylvania'),
        ('PR', 'Puerto Rico'),
        ('RI', 'Rhode Island'),
        ('SC', 'South Carolina'),
        ('SD', 'South Dakota'),
        ('TN', 'Tennessee'),
        ('TX', 'Texas'),
        ('UT', 'Utah'),
        ('VA', 'Virginia'),
        ('VI', 'U.S. Virgin Islands'),
        ('VT', 'Vermont'),
        ('WA', 'Washington'),
        ('WI', 'Wisconsin'),
        ('WV', 'West Virginia'),
        ('WY', 'Wyoming'),
    )

    asmt_id = models.CharField(
        max_length=8,
        validators=[
            RegexValidator(
                regex="^(?:[0-9]+){7}",
                # regex rules:
                # \d* any digit [0-9]
                # {7} seven digits
                message="Please provide a valid assessment ID. The ID should be a 7-digit numerical value.",
                code="invalid_id",
            )
        ],
        unique=True,
    )
    # report_name = models.CharField(max_length=50,
    #                                    validators=[MinLengthValidator(13)],
    #                                    verbose_name="Create Assessment ID",
    #                                    )
    report_password = models.CharField(
        max_length=50,
        validators=[MinLengthValidator(13)],
        verbose_name="Create Report Password",
        help_text="Must be at least 13 characters",
    )
    confirm_report_password = models.CharField(
        max_length=50,
        validators=[MinLengthValidator(13)],
        verbose_name="Confirm Report Password",
        help_text="Passwords Must Match",
        default="",
    )
    traffic_light_protocol = models.CharField(
        max_length=20,
        verbose_name="Traffic Light Protocol",
        choices=TLP_CHOICES,
        blank=True,
        help_text="Select what TLP marking should be added to the generated report",
        null=True,
    )

    # Stakeholder Information
    customer_long_name = models.CharField(
        max_length=200, blank=True, unique=True, verbose_name="Stakeholder Name"
    )
    customer_initials = models.CharField(
        max_length=20, blank=True, verbose_name="Stakeholder Abbreviation"
    )
    customer_POC_name = models.CharField(
        max_length=100, blank=True, verbose_name="Point of Contact Name"
    )
    customer_POC_email = models.EmailField(
        max_length=100,
        blank=True,
        validators=[EmailValidator()],
        verbose_name="Point of Contact Email",
    )
    customer_state = models.CharField(
        max_length=20,
        blank=True,
        choices=STATE_CHOICES,
        default="PA",
        verbose_name="State"
    )
    customer_sector = models.CharField(
        max_length=20,
        blank=True,
        choices=SECTOR_CHOICES,
        default="",
        verbose_name="Sector"
    )
    customer_ci_type = models.CharField(
        max_length=75,
        blank=True,
        choices=CI_TYPE_CHOICES,
        default="",
        verbose_name="Critical Infrastructure Type"
    )
    customer_ci_subsector = models.CharField(
        max_length=75,
        blank=True,
        choices=CI_SUBSECTOR_CHOICES,
        default="",
        verbose_name="Critical Infrastructure Subsector"
    )
    customer_location = models.CharField(
        max_length=200,
        blank=True,
        default="",
        verbose_name="On-Site Testing Address"
    )

    # Test Details
    team_lead_name = models.CharField(
        max_length=50, blank=True, unique=True, verbose_name="Team Lead Name"
    )
    team_lead_email = models.EmailField(
        max_length=50,
        blank=True,
        validators=[EmailValidator()],
        verbose_name="Team Lead Email Address",
    )
    business_goal = models.TextField(blank=True, verbose_name="Business Goal")

    # External Assessment
    ext_start_date = models.DateField(
        default=datetime.date.today,
        max_length=10,
        blank=True,
        verbose_name="External Start Date",
        null=True,
    )
    ext_end_date = models.DateField(
        default=datetime.date.today() + datetime.timedelta(days=4),
        max_length=10,
        blank=True,
        verbose_name="External End Date",
        null=True,
    )
    ext_scope = models.TextField(
        blank=True,
        verbose_name="External In Scope IP Addresses/Domain Names",
        help_text="Enter as a list of IPs, Ranges, and/or CIDRs",
        null=True,
    )
    ext_excluded_scope = models.TextField(
        blank=True,
        verbose_name="External Out of Scope IP Addresses/Domain Names",
        help_text="Enter as a list of IPs, Ranges, and/or CIDRs",
        null=True,
    )
    web_app_scope = models.TextField(
        blank=True,
        verbose_name="In Scope Web Applications",
        help_text="Enter as a list of domains and/or IPs",
        null=True,
    )
    osinf_scope = models.TextField(
        blank=True,
        verbose_name="In Scope Domains for OSINF",
        help_text="Enter as a list of domains",
        null=True,
    )

    # Internal Assessment
    int_start_date = models.DateField(
        default=datetime.date.today() + datetime.timedelta(days=7),
        max_length=10,
        blank=True,
        verbose_name="Internal Start Date",
        null=True,
    )
    int_end_date = models.DateField(
        default=datetime.date.today() + datetime.timedelta(days=11),
        max_length=10,
        blank=True,
        verbose_name="Internal End Date",
        null=True,
    )
    int_scope = models.TextField(
        blank=True,
        verbose_name="Internal In Scope IP Addresses/Domain Names",
        help_text="Enter as a list of IPs, Ranges, and/or CIDRs",
        null=True,
    )
    int_excluded_scope = models.TextField(
        blank=True,
        verbose_name="Internal Out of Scope IP Addresses/Domain Names",
        help_text="Enter as a list of IPs, Ranges, and/or CIDRs",
        null=True,
    )

    phishing_domains = models.TextField(
        blank=True,
        verbose_name="In Scope Mail Domains for Phishing",
        help_text="Enter a list of mail domains associated with in-scope phishing targets",
        null=True,
    )

    fy = models.PositiveIntegerField(
        default=current_year(),
        verbose_name='Fiscal Year',
        blank=True,
        validators=[MinValueValidator(1984), max_value_current_year()],
    )

    class Meta:
        verbose_name_plural = 'Engagement Metadata'
        ordering = ['asmt_id']

    @classmethod
    def object(cls):
        return (
            cls._default_manager.all().first()
        )  # since there is only one engagement object

    def __str__(self):
        return f"RV {str(self.asmt_id)}: {self.customer_long_name}"

    def get_int_scope(self):
        return self.int_scope

    def get_ext_scope(self):
        return self.ext_scope

    def get_int_excluded_scope(self):
        return self.int_excluded_scope

    def get_ext_excluded_scope(self):
        return self.ext_excluded_scope

    def save(self, *args, **kwargs):
        # to always run full clean before creating or saving to model
        super().full_clean()
        self.updated_at = timezone.now()
        self.id = 1
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse("engagement")


STATUS_CHOICES = (
    ('Canceled', "Canceled"),
    ('Completed', "Completed"),
    ('In Progress', "In Progress"),
    ('Not Started', "Not Started"),
    ('On Hold', "On Hold"),
)


class HVAData(models.Model):
    asmt_id = models.CharField(max_length=255)
    agency = models.CharField(max_length=255, blank=True)
    # TODO NEXT RELEASE--
    target = models.ManyToManyField(
        HVATarget,
        verbose_name='HVA Target(s)',
        help_text='What are the designated high valued asset targets?',
        blank=True,
    )
    federal_lead = models.CharField(max_length=255, blank=True)

    # Scenario - Susceptibility
    external_suscep = models.BooleanField(
        null=True,
        default=None,
        verbose_name='Susceptibility to External Threats',
        help_text='Is this HVA susceptibile to external threats?',
        blank=True,
    )
    phish_suscep = models.BooleanField(
        null=True,
        default=None,
        verbose_name='Susceptibility to Phishing Threats',
        help_text='Is this HVA susceptibile to phishing threats?',
        blank=True,
    )
    web_suscep = models.BooleanField(
        null=True,
        default=None,
        verbose_name='Susceptibility to Web Application Threats',
        help_text='Is this HVA susceptibile to web application threats?',
        blank=True,
    )
    internal_suscep = models.BooleanField(
        null=True,
        default=None,
        verbose_name='Susceptibility to Internal Threats',
        help_text='Is this HVA susceptibile to internal threats?',
        blank=True,
    )
    internal_emaulation_suscep = models.BooleanField(
        null=True,
        default=None,
        verbose_name='Susceptibility to Internal Emulation Threats (ITE)',
        help_text='Is this HVA susceptibile to internal emulation threats?',
        blank=True,
    )
    data_exfil_suscep = models.BooleanField(
        null=True,
        default=None,
        verbose_name='Susceptibility to Data Exfiltration Threats',
        help_text='Is this HVA susceptibile to data exfiltration threats?',
        blank=True,
    )

    # Scenario - Findings
    external_findings = models.ManyToManyField(
        findings.UploadedFinding,
        verbose_name='External Assessment Scenario Findings',
        help_text='What are the findings related to the external assessment scenario?',
        blank=True,
        related_name='related_external_findings',
    )
    phish_findings = models.ManyToManyField(
        findings.UploadedFinding,
        verbose_name='Phishing Scenario Findings',
        help_text='What are the findings related to the phishing campaign scenario?',
        blank=True,
        related_name='related_phishing_findings',
    )
    web_findings = models.ManyToManyField(
        findings.UploadedFinding,
        verbose_name='Web App Scenario Findings',
        help_text='What are the findings related to the web app scenario?',
        blank=True,
        related_name='related_web_app_findings',
    )
    internal_findings = models.ManyToManyField(
        findings.UploadedFinding,
        verbose_name='Internal Assessment Scenario Findings',
        help_text='What are the findings related to the internal assessment scenario?',
        blank=True,
        related_name='related_internal_findings',
    )
    internal_emulation_findings = models.ManyToManyField(
        findings.UploadedFinding,
        verbose_name='Internal Emultional Scenario Findings',
        help_text='What are the findings related to the internal emulation scenario?',
        blank=True,
        related_name='related_internal_emulation_findings',
    )
    data_exfil_findings = models.ManyToManyField(
        findings.UploadedFinding,
        verbose_name='Data Exfiltration Scenario Findings',
        help_text='What are the findings related to the data exfiltration scenario?',
        blank=True,
        related_name='related_data_exfil_findings',
    )

    @classmethod
    def object(cls):
        return cls._default_manager.all().first()  # since there is only one HVA object

    class Meta:
        verbose_name_plural = 'HVA Details'

    def __str__(self):
        return f"HVA {str(self.asmt_id)}: {self.agency}"


def get_engagement_dates(instance):
    print('instance: ', instance)

    start_date = (
        instance.int_start_date
        if instance.int_start_date < instance.ext_start_date
        else instance.ext_start_date
    )
    end_date = (
        instance.ext_end_date
        if instance.ext_end_date > instance.int_end_date
        else instance.int_end_date
    )
    engagement_dates = (
        f"{start_date.strftime('%m/%d/%Y')} to {end_date.strftime('%m/%d/%Y')}"
    )

    return engagement_dates


#@receiver(signals.pre_save, sender=EngagementMeta)
#def pre_save_engagement(sender, instance, **kwargs):
#    date = instance.int_end_date
#    month = date.month
#    if month < 10:
#        instance.fy = date.year
#    else:
#        instance.fy = date.year + 1


#@receiver(signals.post_save, sender=EngagementMeta)
#def post_save_engagement(sender, instance, **kwargs):
#    r = report.Report.object()
#    if r.report_type == 'HVA':
#        if HVAData.objects.exists():
#            hva_obj = HVAData.objects.first()
#            hva_obj.asmt_id = instance.asmt_id
#            hva_obj.agency = instance.customer_long_name
#            hva_obj.federal_lead = instance.team_lead_name
#            hva_obj.save()
#        else:
#            hva_obj = HVAData.objects.create(
#                asmt_id=instance.asmt_id,
#                agency=instance.customer_long_name,
#                federal_lead=instance.team_lead_name,
#            )
#    if HVATarget.objects.exists():
#        hva_obj.target.add(*HVATarget.objects.all())


#@receiver(signals.pre_delete, sender=EngagementMeta)
#def pre_delete_engagement(sender, instance, **kwargs):
#    if instance.customer_initials:
#        scenarios = report.AssessmentScenarios.objects.all()
#        for i in scenarios:
#            i.scenario = i.scenario.replace(
#                instance.customer_initials, "{{eng_meta.customer_initials}}"
#            )
#            i.save()


@receiver(signals.post_delete, sender=EngagementMeta)
def post_delete_engagement(sender, instance, **kwargs):

    HVAData.objects.all().delete()
    HVATarget.objects.all().delete()
