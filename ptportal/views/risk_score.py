# Risk & Vulnerability Reporting Engine

# Copyright 2022 Carnegie Mellon University.

# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

# Released under a BSD (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.

# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.

# Carnegie Mellon® is registered in the U.S. Patent and Trademark Office by Carnegie Mellon University.

# This Software includes and/or makes use of Third-Party Software each subject to its own license.

# DM22-0744
from django.core.exceptions import ValidationError
from django.views import generic
from django.http import HttpResponse, JsonResponse
import json

from ..models import UploadedFinding


class RiskScoring(generic.base.TemplateView):
    template_name = 'ptportal/risk_score.html'

    def get_context_data(self, **kwargs):
        context = {}
        context['findings'] = UploadedFinding.objects.all().order_by('severity', 'assessment_type', 'uploaded_finding_name', 'created_at')

        missing_magnitude = []
        missing_likelihood = []

        for f in context['findings']:
            if f.magnitude == "":
                missing_magnitude.append(f.uploaded_finding_name)
            if f.likelihood == None:
                missing_likelihood.append(f.uploaded_finding_name)

        context['missing_magnitude'] = ', '.join(missing_magnitude)
        context['missing_likelihood'] = ', '.join(missing_likelihood)

        return context

    def post(self, request, *args, **kwargs):
        postData = json.loads(request.body)

        for order, finding in enumerate(postData):
            if (
                finding['uploaded_finding_id']
                == finding['uploaded_finding_name']
                == finding['severity']
                == finding['magnitude']
                == finding['likelihood']
                == finding['kev']
                == finding['risk_score']
                == ""
            ):
                continue

            if finding['kev'] == 'True':
                likelihood = 100
            elif finding['likelihood'] == '':
                likelihood = None
            elif (int(finding['likelihood']) < 0 or int(finding['likelihood']) > 100):
                return HttpResponse(status=400, reason="Likelihood must be integer between 1 and 100.")
            else:
                try:
                    likelihood = int(finding['likelihood'])
                except:
                    likelihood = 1

            try:
                update_finding = UploadedFinding.objects.get(uploaded_finding_id=finding['uploaded_finding_id'])
                update_finding.magnitude = finding['magnitude']
                update_finding.likelihood = likelihood
                update_finding.save()

            except (KeyError, ValidationError) as e:
                return HttpResponse(status=400, reason=e)
                
        return HttpResponse(status=200)
        