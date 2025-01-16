# Risk & Vulnerability Reporting Engine

# Copyright 2022 Carnegie Mellon University.

# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

# Released under a BSD (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.

# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

# Carnegie Mellon® is registered in the U.S. Patent and Trademark Office by Carnegie Mellon University.

# This Software includes and/or makes use of Third-Party Software each subject to its own license.

# DM22-0744
from itertools import zip_longest

from django.http import JsonResponse
from django.shortcuts import redirect, get_object_or_404
from django.views import generic
from django.contrib import messages
from django.core import serializers
from django.template.defaultfilters import slugify
from django.http import HttpResponse
from django.urls import reverse_lazy, reverse
from django.db.models.functions import Lower
import json
from ptportal.forms import NarrativeForm
from ptportal.models import NarrativeBlock, NarrativeBlockStep, Narrative, NarrativeType, Tools, ATTACK, NarrativeStep, Report


def ajax_get_narrative_images(request):
    narrative = Narrative.objects.filter(slug=request.GET.get('narrative')).first()
    images = NarrativeScreenshot.objects.filter(narrative=narrative).values()
    data = {}
    data['images'] = list(images)
    return JsonResponse(data, safe=False)


def ajax_delete_narrative_images(request):
    if NarrativeScreenshot.objects.filter(file=request.POST.get('image')).exists():
        image = NarrativeScreenshot.objects.filter(file=request.POST.get('image')).first()
        image.delete()
        return JsonResponse({})
    else:
        return JsonResponse({})


class NarrativeCreate(generic.edit.CreateView):
    model = Narrative
    form_class = NarrativeForm
    template_name = 'ptportal/narrative/narrative_form.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['all_tools'] = serializers.serialize("json", Tools.objects.all())
        context['techniques'] = serializers.serialize("json", ATTACK.objects.all())

        return context

    def post(self, request, *args, **kwargs):
        postData = json.loads(request.POST['data'])

        try:
            diagram = request.FILES['file']
        except Exception as e:
            print(e)
            diagram = False

        order = Narrative.objects.filter(assessment_type__slug=self.kwargs['narrative_assessment_type']).count() + 1
        narrative_type = NarrativeType.objects.filter(slug=self.kwargs['narrative_assessment_type']).first()

        if diagram:
            try:
                narrative = Narrative.objects.create(
                            assessment_type = narrative_type,
                            order = order,
                            name = str(self.kwargs['narrative_assessment_type']).capitalize() + " Attack Path",
                            file = diagram,
                            caption = postData['imageUpload'][0]['caption'],
                        )
            except Exception as e:
                print(e)

        else:
            try:
                narrative = Narrative.objects.create(
                            assessment_type = narrative_type,
                            order = order,
                            name = str(self.kwargs['narrative_assessment_type']).capitalize() + " Attack Path",
                        )
            except Exception as e:
                print(e)
                return HttpResponse(status=500)


        techniques = []
        tools = []

        for i in postData['newTools']:
            if (Tools.objects.filter(name=i['toolName']).exists()):
                try:
                    tool = Tools.objects.get(name=i['toolName'])
                    tool.url=i['toolURL']
                    tool.save()
                except Exception as e:
                    print(e)
                    continue
            else:
                try:
                    Tools.objects.create(
                        name=i['toolName'],
                        url=i['toolURL']
                    )
                except Exception as e:
                    print(e)
                    continue

        for i in postData['tools']:
            tool = Tools.objects.get(name=i)
            try:
                tools.append(Tools.objects.get(
                    name=i)
                )
            except Exception as e:
                print(e)
                continue

        try:
            narrative.tools.add(*tools)
        except Exception as e:
            print(e)

        for i in postData['techniques']:
            try:
                techniques.append(ATTACK.objects.get(
                    name=i)
                )
            except Exception as e:
                print(e)
                continue

        try:
            narrative.attack.add(*techniques)
        except Exception as e:
            print(e)

        return HttpResponse(status=200)


class NarrativeEdit(generic.edit.UpdateView):
    model = Narrative
    form_class = NarrativeForm
    template_name = 'ptportal/narrative/narrative_form.html'

    def get_object(self):
        return get_object_or_404(
            Narrative,
            assessment_type__slug=self.kwargs['narrative_assessment_type'],
            slug=self.kwargs['narrative_name'],
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        narrative = self.get_object()
        context['breadcrumb'] = str(self.get_object().assessment_type.name)
        context['name'] = str(self.get_object().name) + " " + str(self.get_object().order)
        context['diagram'] = narrative.file
        context['all_tools'] = serializers.serialize("json", Tools.objects.all().order_by(Lower('name')))
        context['used_tools'] = serializers.serialize("json", narrative.tools.all())
        context['techniques'] = serializers.serialize("json", ATTACK.objects.all())

        blocks = NarrativeStep.objects.filter(narrative=narrative).values_list('narrative_block', flat=True).distinct().order_by()
        block_list = list(blocks)

        recommended_tools = []
        recommended_techs = []

        for b in block_list:
            try:
                narrative_block = NarrativeBlock.objects.filter(name=b).first()
                recommended_tools.extend(list(narrative_block.tools.all().values_list('name', flat=True)))
                recommended_techs.extend(list(narrative_block.attack.all().values_list('name', flat=True)))
            except:
                continue

        context['recommended_tools'] = list(set(recommended_tools))
        context['recommended_techs'] = list(set(recommended_techs))

        missing = []

        if narrative.file == "":
            missing.append("Attack Path Diagram")
        if narrative.file != "" and narrative.caption == "":
            missing.append("Attack Path Diagram Caption")
        if narrative.tools.values_list().count() == 0:
            missing.append("Tools")
        if narrative.attack.values_list().count() == 0:
            missing.append("MITRE ATT&CK Techniques")

        context['missing'] = ', '.join(missing)

        return context

    def post(self, request, *args, **kwargs):
        postData = json.loads(request.POST['data'])

        try:
            diagram = request.FILES['file']
        except Exception as e:
            print(e)
            diagram = False

        narrative = self.get_object()
        techniques = []
        tools = []

        if postData['deleteImage'] == True:
            narrative.file.delete()

        if diagram:
            try:
                narrative.file = diagram
            except Exception as e:
                print(e)

        try:
            narrative.caption = postData['imageUpload'][0]['caption']
        except Exception as e:
            print(e)

        for i in postData['newTools']:
            if (Tools.objects.filter(name=i['toolName']).exists()):
                try:
                    tool = Tools.objects.get(name=i['toolName'])
                    tool.url=i['toolURL']
                    tool.save()
                except Exception as e:
                    print(e)
                    continue
            else:
                try:
                    Tools.objects.create(
                        name=i['toolName'],
                        url=i['toolURL']
                    )
                except Exception as e:
                    print(e)
                    continue

        for i in postData['tools']:
            try:
                tools.append(Tools.objects.get(
                    name=i)
                )
            except Exception as e:
                print(e)
                continue

        tool_backup = narrative.tools.all()

        try:
            narrative.tools.clear()
            narrative.tools.add(*tools)
        except Exception as e:
            print(e)
            narrative.tools.set(list(tool_backup))

        for i in postData['techniques']:
            try:
                techniques.append(ATTACK.objects.get(
                    name=i)
                )
            except Exception as e:
                print(e)
                continue

        attack_backup = narrative.attack.all()
        
        try:
            narrative.attack.clear()
            narrative.attack.add(*techniques)
        except Exception as e:
            print(e)
            narrative.attack.set(list(attack_backup))

        narrative.save()

        return HttpResponse(status=200)


class NarrativeSteps(generic.base.TemplateView):
    model = Narrative
    template_name = 'ptportal/narrative/narrative_steps.html'

    def get_object(self):
        return get_object_or_404(
            Narrative,
            assessment_type__slug=self.kwargs['narrative_assessment_type'],
            slug=self.kwargs['narrative_name'],
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['breadcrumb'] = str(self.get_object().assessment_type.name)
        context['name'] = str(self.get_object().name) + " " + str(self.get_object().order)
        context['steps'] = NarrativeStep.objects.filter(narrative=self.get_object())
        context['blocks'] = NarrativeBlock.objects.all()
        context['block_steps'] = NarrativeBlockStep.objects.all().order_by('narrative_block__name', 'order')
        context['report'] = Report.objects.all().first()
        
        blocks = NarrativeStep.objects.filter(narrative=self.get_object()).values_list('narrative_block', flat=True).distinct().order_by()
        block_list = list(blocks)

        recommended_tools = []
        recommended_techs = []

        for b in block_list:
            try:
                narrative_block = NarrativeBlock.objects.filter(name=b).first()
                recommended_tools.extend(list(narrative_block.tools.all().values_list('name', flat=True)))
                recommended_techs.extend(list(narrative_block.attack.all().values_list('name', flat=True)))
            except:
                continue

        context['recommended_tools'] = list(set(recommended_tools))
        context['recommended_techs'] = list(set(recommended_techs))

        missing_description = []
        missing_caption = []

        for s in context['steps']:
            if s.description == "":
                missing_description.append(str(s.order))
            if s.file != "" and s.caption == "":
                missing_caption.append(str(s.order))

        context['missing_description'] = ', '.join(missing_description)
        context['missing_caption'] = ', '.join(missing_caption)

        return context

    def post(self, request, *args, **kwargs):
        postData = json.loads(request.POST['data'])

        narrative = self.get_object()
        uploadedSteps = []

        for index, data in enumerate(postData):
            if data['uuid'] is not None:
                obj = NarrativeStep.objects.get(uuid=data['uuid'])
                obj.order = index + 1
                obj.description = data['description']
                obj.screenshot_help = data['recommendation']
                obj.caption = data['caption']
                obj.narrative_block = data['narrative_block']
                if data['imgOrder'] is not None:
                    filename = "file" + str(data['imgOrder'])
                    file = request.FILES[filename]
                    obj.file = file
                obj.save()
                uploadedSteps.append(obj)

            else:
                if data['imgOrder'] is not None:
                    filename = "file" + str(data['imgOrder'])
                    file = request.FILES[filename]
                    obj = NarrativeStep.objects.create(
                        order = index + 1,
                        description = data['description'],
                        screenshot_help = data['recommendation'],
                        caption = data['caption'],
                        file = file,
                        narrative = narrative,
                        narrative_block = data['narrative_block']
                    )

                else:
                    obj = NarrativeStep.objects.create(
                        order = index + 1,
                        description = data['description'],
                        screenshot_help = data['recommendation'],
                        caption = data['caption'],
                        narrative = narrative,
                        narrative_block = data['narrative_block']
                    )

                uploadedSteps.append(obj)

        deletedSteps = set(NarrativeStep.objects.filter(narrative=self.get_object())) - set(uploadedSteps)

        for deleted in deletedSteps:
            deleted.delete()

        return HttpResponse(status=200)


class NarrativeDelete(generic.edit.DeleteView):
    model = Narrative
    template_name = 'ptportal/narrative/narrative_confirm_delete.html'
    success_url = reverse_lazy('index')

    def get_object(self):
        return get_object_or_404(
            Narrative,
            assessment_type__slug=self.kwargs['narrative_assessment_type'],
            slug=self.kwargs['narrative_name'],
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context

    def delete(self, request, *args, **kwargs):
        narrative = self.get_object()
        order = narrative.order
        assessment_type = narrative.assessment_type
        slug = narrative.assessment_type.slug
        super().delete(request, *args, **kwargs)
        
        for i in Narrative.objects.filter(assessment_type=assessment_type):
            if order < i.order:
                try:
                    i.order -= 1
                    i.save()
                except:
                    continue
        return redirect(reverse('narratives', args=(slug,)))


class Narratives(generic.ListView):
    model = Narrative
    template_name = 'ptportal/narrative/narrative_list.html'

    def get_queryset(self):
        self.assessment_type = get_object_or_404(NarrativeType, slug=self.kwargs['narrative_assessment_type'])
        return Narrative.objects.filter(assessment_type=self.assessment_type)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['narrative_assessment_type'] = get_object_or_404(
            NarrativeType, slug=self.kwargs['narrative_assessment_type']
        )

        self.assessment_type = get_object_or_404(NarrativeType, slug=self.kwargs['narrative_assessment_type'])
        context['paths'] = Narrative.objects.filter(assessment_type=self.assessment_type)

        missing_details = []
        missing_steps = []
        missing_step_info = []

        for n in context['paths']:
            steps = NarrativeStep.objects.filter(narrative=n)
            if n.file == "" or n.caption == "" or n.tools.values_list().count() == 0 or n.attack.values_list().count() == 0:
                missing_details.append(str(n.order))
            if steps.values_list().count() == 0:
                missing_steps.append(str(n.order))
            for s in steps:
                if s.description == "":
                    missing_step_info.append(str(n.order))
                    break
                elif s.file != "" and s.caption == "":
                    missing_step_info.append(str(n.order))
                    break

        context['missing_details'] = ', '.join(missing_details)
        context['missing_steps'] = ', '.join(missing_steps)
        context['missing_step_info'] = ', '.join(missing_step_info)

        return context
