# Risk & Vulnerability Assessment Reporting Engine

# Copyright 2022 The Risk & Vulnerability Reporting Engine Contributors, All Rights Reserved.
# (see Contributors.txt for a full list of Contributors)

# SPDX-License-Identifier: BSD-3-Clause

# Please see additional acknowledgments (including references to third party source code, object code, documentation and other files) in the license.txt file or contact permission@sei.cmu.edu for full terms.

# Created, in part, with funding and support from the United States Government. (see Acknowledgments file).

# DM22-1011

from django.db import models
from django.template.defaultfilters import slugify
from django.urls import reverse
from . import abstract_models
import uuid


def define_uploadpath(instance, filename):
    return f"screenshots/narrative/{instance.slug}/{str(instance.uuid) + '.' + filename.split('.')[-1]}"


def define_uploadpath_steps(instance, filename):
    return f"screenshots/narrative/steps/{instance.narrative.slug}/{str(instance.uuid) + '.' + filename.split('.')[-1]}"


class NarrativeType(models.Model):
    NARRATIVE_TYPE_CHOICES = (
        ('External', "External"),
        ('Internal', "Internal"),
        ('Phishing', "Phishing"),
    )
    name = models.CharField(
        max_length=255,
        choices=NARRATIVE_TYPE_CHOICES,
        blank=False,
        verbose_name="Narrative Type",
    )
    slug = models.SlugField(max_length=255, blank=True)

    class Meta:
        verbose_name_plural = 'Narrative Types'
        ordering = ['name']

    def __str__(self):
        return f"{self.name} Narrative"

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        super().full_clean()
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse('narratives', args=[self.slug])


class Tools(models.Model):
    name = models.CharField(max_length=150, blank=True, unique=True)
    url = models.CharField(max_length=200, blank=True)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        super().full_clean()
        super().save(*args, **kwargs)

    class Meta:
        verbose_name_plural = 'Tools'
        ordering = ['name']


class ATTACK(models.Model):
    t_id = models.CharField(verbose_name="MITRE ATT&CK Technique ID", max_length=20, unique=True)
    name = models.CharField(verbose_name="MITRE ATT&CK Technique Name", max_length=200, unique=True)
    tactics = models.CharField(verbose_name="MITRE ATT&CK Tactic(s)", max_length=200)
    description = models.TextField(verbose_name="MITRE ATT&CK Technique Description", max_length=4000, blank=True)
    url = models.CharField(verbose_name="MITRE ATT&CK Technique URL", max_length=100, blank=True)
    is_subtechnique = models.BooleanField(default=False, blank=True)

    def __str__(self):
        return f"{self.t_id}: {self.name}"

    class Meta:
        verbose_name_plural = 'ATT&CK Techniques'


class NarrativeBlock(abstract_models.TimeStampedModel):
    name = models.CharField(max_length=200)

    tools = models.ManyToManyField(
        Tools,
        verbose_name='Tools',
        blank=True
    )

    attack=models.ManyToManyField(
        ATTACK,
        verbose_name='MITRE ATT&CK Technique',
        blank=True
    )

    class Meta:
        verbose_name_plural = "Narrative Blocks"
        ordering = ['name']

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        super().full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class NarrativeBlockStep(abstract_models.TimeStampedModel):
    narrative_block = models.ForeignKey(
        NarrativeBlock, 
        null=True, 
        blank=True,
        related_name="steps",
        on_delete=models.CASCADE,
        verbose_name="Associated Narrative Block",
    )

    order = models.PositiveIntegerField(blank=True, default=1)

    description = models.CharField(
        max_length=5000, verbose_name="Step Description", blank=True
    )
    screenshot_help = models.CharField(
        max_length=500, verbose_name="Screenshot Help Text", blank=True
    )
    file = models.ImageField(upload_to=define_uploadpath_steps, blank=True)
    caption = models.CharField(max_length=250, blank=True)
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    class Meta:
        verbose_name_plural = "Narrative Block Steps"
        ordering = ['narrative_block', 'order']

    def __str__(self):
        return f"{self.narrative_block.name}: Step {self.order}"    


class Narrative(abstract_models.TimeStampedModel):
    assessment_type = models.ForeignKey(
        NarrativeType, null=True, blank=True, on_delete=models.SET_NULL
    )

    order = models.PositiveIntegerField(blank=True, default=1)

    name = models.CharField(
        max_length=255, verbose_name="Name of Narrative Section", blank=False
    )

    slug = models.SlugField(max_length=255, blank=True)

    file = models.ImageField(upload_to=define_uploadpath, blank=True)
    caption = models.CharField(max_length=250, blank=True)
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    tools = models.ManyToManyField(
        Tools,
        verbose_name='Tools',
        help_text='What tools were used for this attack path?',
        blank=True,
    )

    attack = models.ManyToManyField(
        ATTACK,
        verbose_name='MITRE ATT&CK Technique',
        blank=True
    )
    
    class Meta:
        verbose_name_plural = "Narratives"
        ordering = ['order']

    def __str__(self):
        return f"{self.assessment_type}: {self.name} {self.order}"

    def save(self, *args, **kwargs):
        self.slug = '-'.join((slugify(self.assessment_type), slugify(self.name), slugify(self.order)))
        super().full_clean()
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse('narrative_edit', [self.assessment_type.slug, self.slug])


class NarrativeStep(abstract_models.TimeStampedModel):
    narrative = models.ForeignKey(
        Narrative, 
        null=True, 
        blank=True,
        related_name="steps",
        on_delete=models.CASCADE,
        verbose_name="Associated Narrative",
    )

    narrative_block = models.CharField(
        max_length=500, verbose_name="Associated Narrative Block", null=True, blank=True
    )

    order = models.PositiveIntegerField(blank=True, default=1)

    description = models.CharField(
        max_length=5000, verbose_name="Step Description", blank=True
    )
    screenshot_help = models.CharField(
        max_length=500, verbose_name="Screenshot Help Text", blank=True
    )
    file = models.ImageField(upload_to=define_uploadpath_steps, blank=True)
    caption = models.CharField(max_length=250, blank=True)
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    class Meta:
        verbose_name_plural = "Narrative Steps"
        ordering = ['narrative', 'order']

    def __str__(self):
        return f"{self.narrative.name} {self.narrative.order}: Step {self.order}"

