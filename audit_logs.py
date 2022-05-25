#!/usr/bin/env python3
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed, jdout
import yaml
import cloudgenix_settings
import sys
import logging
import collections
import os
import datetime
import time
from copy import deepcopy
import json

# Global Vars
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example script: Audit Logs'
SCRIPT_VERSION = "v1"
EPOCH = datetime.datetime(1970, 1, 1)
SYSLOG_DATE_FORMAT = '%b %d %H:%M:%S'

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

def update_parse_audit(last_reported_event, cgx):
    
    id_2name = {}
    for operator in cgx.get.tenant_operators().cgx_content["items"]:
        id_2name[operator["id"]] = operator["email"]
        
    current_datetime_mark = datetime.datetime.utcnow()
    # Access log requires EPOCH timestamp in ms
    current_time_mark = (current_datetime_mark - EPOCH).total_seconds() * 1000
    parsed_events = []

    print("Query Start: " + str(last_reported_event) + " and Query End: " + str(current_datetime_mark))

    # add 1 second to make sure we don't get the same event over and over)
    start_time = ((last_reported_event + datetime.timedelta(seconds=1)) - EPOCH).total_seconds() * 1000
    
    audit_query_tpl = {
        "limit": "100",
        "query_params": {
            "request_ts": {
                "gte": 152000000000
            },
            "response_ts": {
                "lte": 1525722908000
            }
        },
        "sort_params": {
            "response_ts": "desc"
        },
        "dest_page": 1
    }
    
    query = deepcopy(audit_query_tpl)
    query["query_params"]["request_ts"]["gte"] = start_time
    query["query_params"]["response_ts"]["lte"] = current_time_mark

    audit_list = []

    # get events from last event.
    audit_resp = cgx.post.query_auditlog(query)
    status_audit = audit_resp.cgx_status
    raw_audit = audit_resp.cgx_content
    
    
    if status_audit:
        raw_audit_items = []

        cur_audit_items = raw_audit.get('items', [])

        if cur_audit_items:
            raw_audit_items.extend(cur_audit_items)
        
        if len(cur_audit_items) == 0:
            print("No new audit logs found\n")
            return last_reported_event
        else:
            more_data = True 
                   
        # iterate until no more audit events
        while more_data:
            # increment dest_page in query
            query["dest_page"] += 1
            audit_resp = cgx.post.query_auditlog(query)
            status_audit = audit_resp.cgx_status
            raw_audit = audit_resp.cgx_content

            cur_audit_items = raw_audit.get('items', [])
            if len(cur_audit_items) == 0:
                more_data = False
            else:
                raw_audit_items.extend(cur_audit_items)

        
        parsed_audit_items = []    
        
        # manipulate the log into a standard event format
        for iter_d in raw_audit_items:
            # deepcopy to allow modification
            body = deepcopy(iter_d)
            for k in iter_d.keys():
                if k.startswith('_'):
                    del body[k]
            # remove response body, as it is too long for syslog
            try:
                #del body['response_code']
                #del body['time_ms']
                #del body['request_content_length']
                #del body['response_content_length']
                #del body['response_body']
                #del body['request_body']
                pass
            except:
                print("Failed to modify the body")
            # Change the operator ID to a name 
            event_operatorid = body["operator_id"]
            try:
                body["operator_id"] = id_2name[event_operatorid]
            except:
                print("Failed to get operators name")
                
            event_timestamp = body.get('request_ts', 0)
            if event_timestamp:
                audit_request_datetime = datetime.datetime.utcfromtimestamp(event_timestamp / 1000.0)
            else:
                audit_request_datetime = current_datetime_mark
            body['time'] = audit_request_datetime.isoformat() + 'Z'
            
            parsed_audit_items.append(body)
            
            if audit_request_datetime > last_reported_event:
                last_reported_event = audit_request_datetime
        
        # add current alarms to list
        audit_list.extend(parsed_audit_items)
        
    # sort by create time
    events_list = sorted(audit_list, key=lambda k: k["time"])
    
    for event in events_list:
        print(event["operator_id"] + " " + event["resource_key"])
    
    print(str(len(events_list)) + " new audit logs found\n")
    
    
    ############### you can add wahtever logic now to send events_list to your logging system
    
    
    return last_reported_event
       
                                 
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
    
    # Allow Controller modification and debug level sets.
    config_group = parser.add_argument_group('Config', 'These options change how the configuration is generated.')
                             
    args = vars(parser.parse_args())
    
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # check for token
    if CLOUDGENIX_AUTH_TOKEN:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()
    else:
        print("No AUTH_TOKEN found")
        sys.exit()

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    last_reported_event = datetime.datetime.utcnow()

    while True:
        
        if cgx_session.tenant_id is None:
            if CLOUDGENIX_AUTH_TOKEN:
                cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
                if cgx_session.tenant_id is None:
                    print("AUTH_TOKEN login failure, please check token.")
                    sys.exit()
            else:
                print("No AUTH_TOKEN found")
                sys.exit()
            
        last_reported_event = update_parse_audit(last_reported_event, cgx_session) 
        time.sleep(180)   

if __name__ == "__main__":
    go()