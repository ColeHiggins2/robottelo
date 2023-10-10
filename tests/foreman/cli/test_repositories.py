"""Test module for Repositories CLI.

:Requirement: Repository

:CaseAutomation: Automated

:CaseLevel: Component

:CaseComponent: Repositories

:team: Phoenix-content

:TestType: Functional

:CaseImportance: Critical

:Upstream: No
"""
import pytest
from requests.exceptions import HTTPError

from robottelo.constants import DEFAULT_ARCHITECTURE, REPOS


def test_negative_invalid_repo_fails_publish(
    module_repository,
    module_org,
    target_sat,
):
    """Verify that an invalid repository fails when trying to publish in a content view

    :id: 64e03f28-8213-467a-a229-44c8cbfaaef1

    :steps:
        1. Create custom product and upload repository
        2. Run Katello commands to make repository invalid
        3. Create content view and add repository
        4. Verify Publish fails

    :expectedresults: Publishing a content view with an invalid repository fails

    :customerscenario: true

    :BZ: 2032040
    """
    repo = module_repository
    target_sat.execute(
        'echo "root = ::Katello::RootRepository.last; ::Katello::Resources::Candlepin::Product.'
        'remove_content(root.product.organization.label, root.product.cp_id, root.content_id); '
        '::Katello::Resources::Candlepin::Content.destroy(root.product.organization.label, '
        'root.content_id)" | foreman-rake console'
    )
    cv = target_sat.api.ContentView(
        organization=module_org.name,
        repository=[repo.id],
    ).create()
    with pytest.raises(HTTPError) as context:
        cv.publish()
    assert 'Remove the invalid repository before publishing again' in context.value.response.text


def test_positive_disable_rh_repo_with_basearch(module_target_sat, module_entitlement_manifest_org):
    """Verify that users can disable Red Hat Repositories with basearch

    :id: dd3b63b7-1dbf-4d8a-ab66-348de0ad7cf3

    :steps:
        1.  You have the Appstream Kicstart repositories release version
            "8" synced in from the release of RHEL 8
        2.  hammer repository-set disable --basearch --name --product-id
            --organization --releasever


    :expectedresults: Users can now disable Red Hat repositories with
        basearch

    :customerscenario: true

    :BZ: 1932486
    """
    rh_repo_id = module_target_sat.api_factory.enable_rhrepo_and_fetchid(
        basearch=DEFAULT_ARCHITECTURE,
        org_id=module_entitlement_manifest_org.id,
        product=REPOS['kickstart']['rhel8_aps']['product'],
        repo=REPOS['kickstart']['rhel8_aps']['name'],
        reposet=REPOS['kickstart']['rhel8_aps']['reposet'],
        releasever=REPOS['kickstart']['rhel8_aps']['version'],
    )
    repo = module_target_sat.api.Repository(id=rh_repo_id).read()
    repo.sync(timeout=2000)
    disabled_repo = module_target_sat.execute(
        f'hammer repository-set disable --basearch {DEFAULT_ARCHITECTURE} '
        f'--name "Red Hat Enterprise Linux 8 for x86_64 - BaseOS (Kickstart)" '
        f'--product-id {repo.product.id} '
        f'--organization-id {module_entitlement_manifest_org.id} '
        f'--releasever 8 '
        f'--repository-id {rh_repo_id}'
    )
    assert 'Repository disabled' in disabled_repo.stdout