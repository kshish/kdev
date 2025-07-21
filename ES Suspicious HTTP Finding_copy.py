"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'playbook_lookup_url_in_es_http_intel_collection_1' block
    playbook_lookup_url_in_es_http_intel_collection_1(container=container)

    return

@phantom.playbook_block()
def playbook_lookup_url_in_es_http_intel_collection_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_lookup_url_in_es_http_intel_collection_1() called")

    finding_data = phantom.collect2(container=container, datapath=["finding:consolidated_findings.url"])

    finding_consolidated_findings_url = [item[0] for item in finding_data]

    inputs = {
        "url": finding_consolidated_findings_url,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Lookup url in ES http_intel collection", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Lookup url in ES http_intel collection", container=container, name="playbook_lookup_url_in_es_http_intel_collection_1", callback=decision_1, inputs=inputs)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_lookup_url_in_es_http_intel_collection_1:playbook_output:threat_key", "==", ""]
        ],
        conditions_dps=[
            ["playbook_lookup_url_in_es_http_intel_collection_1:playbook_output:threat_key", "==", ""]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        update_finding_or_investigation_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    update_finding_or_investigation_3(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def update_finding_or_investigation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_finding_or_investigation_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:finding_id"])

    parameters = []

    # build parameters list for 'update_finding_or_investigation_2' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None:
            parameters.append({
                "status": "Closed",
                "urgency": "Informational",
                "id": finding_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update finding or investigation", parameters=parameters, name="update_finding_or_investigation_2", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def update_finding_or_investigation_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_finding_or_investigation_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:finding_id"])

    parameters = []

    # build parameters list for 'update_finding_or_investigation_3' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None:
            parameters.append({
                "status": 2,
                "urgency": "Critical",
                "id": finding_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update finding or investigation", parameters=parameters, name="update_finding_or_investigation_3", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return