#!/usr/bin/env python3.6

"""
Simple python tool to scrapes the Secrets and ConfigMaps defined in namespace
deployment as ENV variables for containers and hunts for suspicious values.
Concretly it's:
  - URI
  - IP
  - DOMAIN name

One can use this tool before migrating the k8s service to another cluster
to verify what external resources availability one should need to check first. 

"""

import base64
import re

import ipaddress
import uritools
import validators

from enum import Enum
from pprint import pprint

from kubernetes import client, config, watch
from kubernetes import client, config
from tabulate import tabulate

SCRAPED_NAMESPACE_REGEX = r'.*-(prod|stage)$'


def decode_base64(base64_message):
    """Basic base64 decode wrapper function."""
    decoded_value = base64.b64decode(
        base64_message.encode('ascii')).decode('ascii')

    return(decoded_value)


def verify_value(value):
    """
    Value verifier.
    We need to figure out whether the value is not one of the:
      - URI
      - IP
      - DOMAIN
    In case it will match one of the above mentioned 'types', we should
    check the value, as it seems to be an external resource for the k8s
    service.
    """
    if uritools.isuri(value):
        return [value, 'URI']
    try:
        ipaddress.ip_address(str(value))
        return [value, 'IP'] 
    except (ipaddress.AddressValueError, ValueError) as e:
        pass 
    if validators.domain(value):
        return [value, 'DOMAIN']

def check_ref_values(ref_data, decoder=str):
    """
    Simple logic that:
      - parses the reference data (Secret or ConfigMap)
      - routes the value to the defined decoder function
      - gathers and filters the empty results and passes them as list
    """
    verified_values = []
    for key, value in ref_data.items():
        decoded_value = decoder(value)
        verified_value = verify_value(decoded_value)
        if verified_value:
            verified_values.append([key] + verified_value)
    return verified_values

def main():
    """Here comes the magic."""
    # Configs can be set in Configuration class directly or using helper utility
    config.load_kube_config()
    core_v1 = client.CoreV1Api()
    apps_v1 = client.AppsV1Api()

    print("---------------------\nListing namespaces\n----------------------")
    ret = core_v1.list_namespace(watch=False)
    for i in ret.items:
        if re.match(SCRAPED_NAMESPACE_REGEX, str(i.metadata.name)):
            suspicious_values = []
            namespace = i.metadata.name
            print(namespace)
            deployment = apps_v1.list_namespaced_deployment(namespace)
            if len(deployment.items) == 0:
                continue
            containers = deployment.items[0].spec.template.spec.containers
            for container in containers:
               if container.env_from == None:
                   continue
               for env_from in container.env_from:
                   if env_from.config_map_ref:
                       config_map_name = env_from.config_map_ref.name 
                       suspicious_values += check_ref_values(
                           core_v1.read_namespaced_config_map(
                               env_from.config_map_ref.name, namespace).data,
                               decoder=str)
                   if env_from.secret_ref:
                       suspicious_values += check_ref_values(
                           core_v1.read_namespaced_secret(
                           env_from.secret_ref.name, namespace).data,
                           decoder=decode_base64)
            print(tabulate(suspicious_values))

#             break


if __name__ == '__main__':
    main()
