from rest_framework import generics
import django_filters.rest_framework
from ..models import AffectedSystem, SpecificFinding, UploadedFinding, Mitigation
from ..serializers import AffectedSystemSerializer, SpecificFindingSerializer, UploadedFindingSerializer, MitigationSerializer


class AffectedSystemListView(generics.ListCreateAPIView):
    queryset = AffectedSystem.objects.all()
    serializer_class = AffectedSystemSerializer
    filterset_fields = '__all__'

class MitigationListView(generics.ListCreateAPIView):
    queryset = Mitigation.objects.all()
    serializer_class = MitigationSerializer
    filterset_fields = '__all__'

class SpecificFindingListView(generics.ListAPIView):
    queryset = SpecificFinding.objects.all()
    serializer_class = SpecificFindingSerializer
    filterset_fields = '__all__'

class UploadedFindingListView(generics.ListCreateAPIView):
    queryset = UploadedFinding.objects.all()
    serializer_class = UploadedFindingSerializer
    filterset_fields = '__all__'

class UploadedFindingUpdateView(generics.UpdateAPIView):
    queryset = UploadedFinding.objects.all()
    serializer_class = UploadedFindingSerializer
    