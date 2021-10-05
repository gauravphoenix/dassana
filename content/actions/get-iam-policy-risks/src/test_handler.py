from unittest import TestCase

from cloudsplaining.output.policy_finding import PolicyFinding
from iteration_utilities import flatten
from policy_sentry.querying.all import get_all_service_prefixes, get_all_actions, get_service_authorization_url
from hypothesis import given, note, strategies as st, settings, assume

from dassana.common.cache import configure_ttl_cache
from handler import cloudsplaining_parse

services = get_all_service_prefixes()
actions = list(get_all_actions())
get_cached_call = configure_ttl_cache()


class IamPolicyRisks(TestCase):

    def __init__(self, *args, **kwargs):
        super(IamPolicyRisks, self).__init__(*args, **kwargs)

    def test_cloudsplaining_parse_simple(self):
        doc = {
            "Statement": [
                {
                    "Action": [
                        "ec2:Create*",
                        "ec2:*",
                        "ec2:Delete*"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ]
        }
        results = cloudsplaining_parse(policy_document=doc).results
        assert (results.get('ServiceWildcard') == ['ec2'])
        assert (results.get('ServicesAffected') == ['ec2'])
        assert (set(results.get('ResourceExposure')) == {'ec2:ModifyVpcEndpointServicePermissions',
                                                         'ec2:ResetSnapshotAttribute',
                                                         'ec2:ModifySnapshotAttribute',
                                                         'ec2:CreateNetworkInterfacePermission'})
        assert (results.get('CredentialsExposure') == ['ec2:GetPasswordData'])
        assert (len(results.get('InfrastructureModification')) == 274)

    @given(st.lists(st.sampled_from(actions), min_size=1))
    @settings(max_examples=5000)
    def test_cloudsplaining_parse_complex(self, acts):
        doc = {
            "Statement": [
                {
                    "Action": acts,
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ]
        }

        results: PolicyFinding = cloudsplaining_parse(policy_document=doc)
        results_t = results.results
        assume(len(results_t.values()) > 0)
        filtered_vals = [value for key, value in results_t.items() if
                         key not in {'ServicesAffected', 'ServicesWildCard', 'PrivilegeEscalation'} and value != []]
        filtered_vals = set(flatten(filtered_vals))
        assume(len(filtered_vals) > 0)
        serv = set(map(lambda x: x.split(':')[0], filtered_vals))
        note(serv.__str__())
        assert (serv == set(results_t.get('ServicesAffected')))
