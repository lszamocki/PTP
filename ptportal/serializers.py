# Risk & Vulnerability Assessment Reporting Engine

# Copyright 2022 The Risk & Vulnerability Reporting Engine Contributors, All Rights Reserved.
# (see Contributors.txt for a full list of Contributors)

# SPDX-License-Identifier: BSD-3-Clause

# Please see additional acknowledgments (including references to third party source code, object code, documentation and other files) in the license.txt file or contact permission@sei.cmu.edu for full terms.

# Created, in part, with funding and support from the United States Government. (see Acknowledgments file).

# DM22-1011
from rest_framework import serializers

from ptportal.models import (
    ElectionInfrastructureQuestionnaire,
    EngagementMeta,
    HVATarget,
    HVAData,
    AffectedSystem,
    Mitigation,
    SpecificFinding,
    UploadedFinding
)


class EngagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = EngagementMeta
        exclude = ['id']


class ElectionInfrastructureSerializer(serializers.ModelSerializer):
    class Meta:
        model = ElectionInfrastructureQuestionnaire
        fields = '__all__'


class HVATargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = HVATarget
        # exclude = ['id']


class HVASerializer(serializers.ModelSerializer):
    class Meta:
        model = HVAData
        fields = "__all__"


class AffectedSystemSerializer(serializers.ModelSerializer):
    class Meta:
        model = AffectedSystem
        fields = "__all__"


class MitigationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Mitigation
        fields = "__all__"


class SpecificFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = SpecificFinding
        fields = "__all__"


class UploadedFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedFinding
        fields = "__all__"

