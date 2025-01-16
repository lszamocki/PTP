# Risk & Vulnerability Assessment Reporting Engine

# Copyright 2022 The Risk & Vulnerability Reporting Engine Contributors, All Rights Reserved.
# (see Contributors.txt for a full list of Contributors)

# SPDX-License-Identifier: BSD-3-Clause

# Please see additional acknowledgments (including references to third party source code, object code, documentation and other files) in the license.txt file or contact permission@sei.cmu.edu for full terms.

# Created, in part, with funding and support from the United States Government. (see Acknowledgments file).

# DM22-1011

from django.db import models
from django.db.models import Sum
from django.template.defaultfilters import slugify
from django.urls import reverse
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.utils.crypto import get_random_string
from .users import *
from collections import defaultdict
from decimal import Decimal

import datetime

from . import abstract_models


class CriticalManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(severity__severity_name='Critical')


class HighManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(severity__severity_name='High')


class MediumManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(severity__severity_name='Medium')


class LowManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(severity__severity_name='Low')


class InformationalManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(severity__severity_name='Informational')


class AffectedSystem(models.Model):
    name = models.CharField(max_length=150, blank=True)
    uid = models.CharField(max_length=20, blank=True)
    ip = models.CharField(max_length=255, blank=True, null=True)
    ip_int = models.BigIntegerField(blank=True, null=True)

    def __str__(self):
        return self.name or self.ip

    def save(self, *args, **kwargs):
        if self.ip:
            sets = [int(x) for x in self.ip.split('.')]
            self.ip_int = (
                sets[0] * 256**3 + sets[1] * 256**2 + sets[2] * 256 + sets[3]
            )
            self.name = self.ip
        if not self.pk:
            self.uid = get_random_string(length=20)
        super().save()

    class Meta:
        verbose_name_plural = 'Affected Systems'
        ordering = ['ip_int', 'name']


class Severities(models.Model):
    order = models.IntegerField(default=0, null=True, blank=True)
    severity_name = models.CharField(
        default="severities", max_length=14, blank=True, unique=True
    )
    severity_description = models.TextField(
        blank=True,
        verbose_name='Severity Description',
        help_text='Description of severity that is used for tooltips',
    )

    class Meta:
        verbose_name_plural = 'Severities'
        ordering = ['order']

    def __str__(self):
        return self.severity_name


class ExternalAssessmentManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(assessment_type='External')


class InternalAssessmentManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(assessment_type='Internal')


class PhishingAssessmentManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(assessment_type='Phishing')


class UploadedFindingsOrderManager(models.Manager):
    def get_preferred_order(self):
        uploaded_findings = UploadedFinding.objects.all()
        order = uploaded_findings.annotate(
            custom_order=models.Case(
                models.When(assessment_type="External", then=models.Value(0)),
                models.When(assessment_type="Internal", then=models.Value(1)),
                models.When(assessment_type="Phishing", then=models.Value(2)),
                default=models.Value(3),
                output_field=models.IntegerField(),
            )
        ).order_by('custom_order', 'severity')
        return order


class KEVMetadata(models.Model):
    title = models.TextField(blank=True)
    catalog_version = models.TextField(blank=True, unique=True)
    date_released = models.DateTimeField(null=True)
    count = models.IntegerField(null=True)

    def __str__(self):
        return f"{self.title}, version: {self.catalog_version}"

    class Meta:
        verbose_name_plural = 'KEV Metadata'


class KEV(models.Model):
    cve_id = models.CharField(max_length=20, unique=True)
    vulnerability_name = models.TextField()
    vendor_project = models.TextField(blank=True)
    product = models.TextField(blank=True)
    date_added = models.DateField(null=True)
    description = models.TextField(blank=True)
    action = models.TextField(blank=True)
    date_action_due = models.DateField(null=True)
    found = models.BooleanField(default=False, blank=True)
    notes = models.TextField(blank=True)
    kev_metadata = models.ForeignKey(KEVMetadata, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.cve_id}, vulnerability name: {self.vulnerability_name}"

    class Meta:
        verbose_name_plural = 'KEVs'


class Category(abstract_models.TimeStampedModel):

    name = models.CharField(max_length=51, unique=True)
    remediation = models.TextField(verbose_name="Remediation", blank=True)
    description = models.TextField(verbose_name="Description", blank=True)
    resources = models.TextField(verbose_name="Resources", blank=True)
    cat_id = models.CharField(
        max_length=50, verbose_name='Category ID', unique=True, default=0
    )

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = 'Finding Categories'


class BaseFinding(abstract_models.TimeStampedModel):
    name = models.CharField(max_length=100)

    finding_id = models.CharField(
        max_length=50, verbose_name='Finding ID', unique=True, default=0
    )

    category = models.ForeignKey(
        Category,
        on_delete=models.CASCADE,
        verbose_name="Category",
        blank=True,
        null=True,
        to_field='name',
    )
    description = models.TextField(verbose_name="Description", blank=True)
    remediation = models.TextField(verbose_name="Standard Remediation", blank=True)
    references = models.TextField(verbose_name="References", blank=True)
    resources = models.TextField(verbose_name="Resources", blank=True)

    severity = models.CharField(max_length=14, default='TBD')
    assessment_type = models.TextField(
        max_length=20, default='TBD'
    )
    timetable = models.TextField(verbose_name="Recommendation Timetable", blank=True)
    default_likelihood = models.IntegerField(
        blank=True, null=True, verbose_name='Default Likelihood', help_text='What is the default likelihood of this finding?'
    )

    NIST_800_53 = models.TextField(blank=True)
    NIST_CSF = models.TextField(blank=True)
    CIS_CSC = models.TextField(blank=True)
    finding_type = models.CharField(max_length=10)
    gen_finding = models.TextField(
        verbose_name="If Specific, what's the general?", blank=True
    )

    tags = models.TextField(blank=True)

    slug = models.SlugField(max_length=255, unique=True, blank=True)

    objects = models.Manager()
    critical = CriticalManager()
    high = HighManager()
    medium = MediumManager()
    low = LowManager()
    informational = InformationalManager()

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        super().full_clean()
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse("index")

    def __str__(self):
        return self.name


class GeneralFinding(BaseFinding):
    general_finding_id = models.IntegerField(
        verbose_name='General Finding ID', unique=True, default=0
    )

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        self.finding_id = str(self.category.cat_id) + "-" + str(self.general_finding_id)
        super().full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class SpecificFinding(BaseFinding):
    specific_finding_id = models.IntegerField(
        verbose_name='Specific Finding ID', unique=True
    )
    general_finding = models.ForeignKey(
        GeneralFinding, on_delete=models.CASCADE, verbose_name="General Finding"
    )

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        self.category = self.general_finding.category
        self.finding_id = (
            str(self.category.cat_id)
            + "-"
            + str(self.general_finding.general_finding_id)
            + "-"
            + str(self.specific_finding_id)
        )
        super().full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = 'Specific Findings'
        ordering = ['name']


class UploadedFinding(abstract_models.TimeStampedModel):

    ASSESSMENT_TYPE_CHOICES = (
        ('External', 'External'),
        ('Internal', 'Internal'),
        ('Phishing', 'Phishing'),
    )

    STATUS_CHOICES = (('Draft', 'Draft'), ('Needs Review', 'Needs Review'), ('Complete', 'Complete'))

    MAGNITUDE_CHOICES = (
        ('', ''),
        ('1-10', '1-10'),
        ('11-20', '11-20'),
        ('21-30', '21-30'),
        ('31+', '31+'),
    )

    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    last_validated = models.DateField(null=True, blank=True, default=datetime.date.today)

    finding = models.ForeignKey(
        BaseFinding,
        to_field='finding_id',
        on_delete=models.CASCADE,
        verbose_name='CISA Finding',
        default='Unspecified',
        help_text='What is the name of this Finding?',
    )

    uploaded_finding_name = models.CharField(max_length=50000)
    uploaded_finding_id = models.IntegerField(default=0)
    duplicate_finding_order = models.IntegerField(default=0)
    manually_added = models.BooleanField(default=True, blank=True)

    NIST_800_53 = models.TextField(blank=True)
    NIST_CSF = models.TextField(blank=True)
    CIS_CSC = models.TextField(blank=True)

    description = models.TextField(
        blank=False,
        verbose_name='Finding Description',
        help_text='Contains the description of this finding from the database. Edit the text below to clarify the description for this specific case.',
    )

    remediation = models.TextField(
        blank=False,
        verbose_name='Finding \n' + 'Remediation',
        help_text='Contains the standard \n'
        + 'remediation of this finding \n'
        + 'from the database. Edit the \n'
        + 'text below to clarify the \n'
        + 'remediation for this specific case',
    )

    operator_notes = models.TextField(
        blank=True,
        verbose_name='Operator Notes',
        help_text='Contains notes for operators that remain internal to the Reporting Engine instance',
    )

    timetable = models.TextField(blank=True, verbose_name='Recommendation Timetable')

    severity = models.ForeignKey(
        Severities,
        to_field='severity_name',
        max_length=14,
        on_delete=models.CASCADE,
        blank=False,
        default='Unspecified',
        help_text='If severity is different than \n'
        + 'default for this finding type, \n'
        + 'select below',
    )

    assessment_type = models.CharField(
        max_length=17,
        choices=ASSESSMENT_TYPE_CHOICES,
        blank=False,
        default='Unspecified',
        verbose_name='Assessment Type',
        help_text='What kind of assessment is this?',
    )

    unmitigated = models.DecimalField(
        verbose_name='Unmitigated Percentage',
        max_digits=4,
        decimal_places=2,
        default=0,
        help_text='What percent of affected systems are not mitigated?',
    )

    status = models.CharField(
        max_length=12,
        choices=STATUS_CHOICES,
        blank=True,
        default='Draft',
        verbose_name='Status',
        help_text='Do the finding details still need to be modified or is it complete?')

    affected_systems = models.ManyToManyField(
        AffectedSystem,
        verbose_name='Affected System',
        help_text='What affected system(s) does this finding relate to?',
        blank=True,
        through='Mitigation'
    )

    screenshot_description = models.TextField(
        blank=True, verbose_name='Screenshot Description'
    )

    KEV = models.ManyToManyField(
        KEV,
        verbose_name='Known Exploited Vulnerability',
        help_text='What KEV(s) pertain to this finding?',
        blank=True
    )

    magnitude = models.CharField(
        choices=MAGNITUDE_CHOICES,
        max_length=5,
        default='',
        blank=True,
        null=True,
        verbose_name='Magnitude',
        help_text='How many occurrences of this finding were discovered?'
    )

    likelihood = models.IntegerField(
        blank=True,
        null=True,
        verbose_name='Likelihood',
        help_text='What is the likelihood that this finding is discovered and abused?'
    )

    risk_score = models.IntegerField(
        default=0,
        blank=True,
        null=True,
        verbose_name='Risk Score'
    )

    mitigated_risk_score = models.IntegerField(
        default=0,
        blank=True,
        null=True,
        verbose_name='Mitigated Risk Score'
    )

    slug = models.SlugField(max_length=255, blank=True)

    objects = UploadedFindingsOrderManager()
    critical = CriticalManager()
    high = HighManager()
    medium = MediumManager()
    low = LowManager()

    informational = InformationalManager()
    external = ExternalAssessmentManager()
    internal = InternalAssessmentManager()
    phishing = PhishingAssessmentManager()

    preferred_order = UploadedFindingsOrderManager()

    def save(self, *args, **kwargs):
        if self.uploaded_finding_id == 0:
            self.uploaded_finding_id = UploadedFinding.objects.all().count() + 1

        self.slug = slugify(self.uploaded_finding_name + "-" + str(self.uploaded_finding_id))

        affected_systems_count = Mitigation.objects.filter(finding=self).count()
        unmitigated_systems_count = Mitigation.objects.filter(finding=self, mitigation=False).count()

        if affected_systems_count > 0:
            percent_unmitigated = unmitigated_systems_count/affected_systems_count
            self.unmitigated = round(Decimal(percent_unmitigated), 2)
        else:
            self.unmitigated = 1


        '''
        ******************************************************************************
         The mappings and risk score formula below should be adjusted based on the
         methodology of the assessing entity. All values are placeholders and do not 
         reflect an actual risk scoring methodology.
        ******************************************************************************
        '''
        
        sev_map = {'Critical': 10, 'High': 9, 'Medium': 8, 'Low': 7, 'Informational': 6}
        mag_map = {'': 0, '1-10': 10, '11-20': 20, '21-30': 30, '31+': 40}
        
        try:
            lkd = self.likelihood/100 + 1
        except Exception as e:
            lkd = 0
            print(e)

        try:
            self.risk_score = int(sev_map[self.severity.severity_name] + lkd + mag_map[self.magnitude])
        except Exception as e:
            self.risk_score = 0
            print(e)

        try:
            self.mitigated_risk_score = int(self.risk_score * self.unmitigated)
        except Exception as e:
            self.mitigated_risk_score = 0
            print(e)

        super().full_clean()
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse("index")

    def __str__(self):
        if self.duplicate_finding_order > 0:
            return self.uploaded_finding_name + " " + str(self.duplicate_finding_order)
        else:
            return self.uploaded_finding_name

    class Meta:
        verbose_name_plural = 'Uploaded Findings'


class Mitigation(models.Model):
    MITIGATION_CHOICES = ((True, 'Yes'), (False, 'No'))
    
    system = models.ForeignKey(AffectedSystem, on_delete=models.CASCADE)
    finding = models.ForeignKey(UploadedFinding, on_delete=models.CASCADE)
    mitigation = models.BooleanField(
        choices=MITIGATION_CHOICES,
        verbose_name='Mitigation',
        default=False,
        help_text='Was this finding mitigated for this affected system?',
    )
    mitigation_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return self.finding.uploaded_finding_name + ": " + self.system.name

    class Meta:
        verbose_name_plural = 'Affected System Mitigation'
        ordering = ['finding', 'system']
