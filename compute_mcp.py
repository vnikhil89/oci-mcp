#!/usr/bin/env python3
"""
OCI Instance MCP Server

A Model Context Protocol server for creating and managing Oracle Cloud Infrastructure instances.
"""

import os
import json
import ssl
import logging
import base64
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv
import oci
import oci.generative_ai_agent_runtime
#from mcp.server.fastmcp import FastMCP
from fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
import random
import smtplib
from email.message import EmailMessage
import time
from datetime import datetime, timezone
from starlette.responses import JSONResponse
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
__project__ = os.getenv("MCP_PROJECT_NAME", "oracle.oci-instance-mcp-server")
__version__ = os.getenv("MCP_VERSION", "0.1.0")

try:
    signer = oci.auth.signers.get_resource_principals_signer()
    config = {}
    logger.info("Using OCI Resource Principal for authentication")
except Exception as e:
    logger.error("Failed to initialize Resource Principal auth")
    raise e

# Global variables to store OCI clients and config (STATIC)
compute_client = oci.core.ComputeClient(config, signer=signer)
storage_client = oci.core.BlockstorageClient(config, signer=signer)
identity_client = oci.identity.IdentityClient(config, signer=signer)
network_client = oci.core.VirtualNetworkClient(config, signer=signer)
os_mgmt_client = oci.os_management_hub.ManagedInstanceClient(config, signer=signer)
monitoring_client = oci.monitoring.MonitoringClient(config, signer=signer)
compute_instance_agent_client = oci.compute_instance_agent.ComputeInstanceAgentClient(config, signer=signer)
agent_runtime_client = oci.generative_ai_agent_runtime.GenerativeAiAgentRuntimeClient(config, signer=signer)
vulnerability_scanning_client = oci.vulnerability_scanning.VulnerabilityScanningClient(config, signer=signer)
osmh_client = oci.os_management_hub.ManagedInstanceClient(config, signer=signer)
agent_endpoint_id = os.getenv("AGENT_ENDPOINT_ID")
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_SENDER = os.getenv("SMTP_SENDER")
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
tenancy_id = os.getenv("OCI_TENANCY_ID")

mcp = FastMCP(name=__project__)
@mcp.tool()
def list_compartments():
    """
    List all compartments in the tenancy.

    Returns:
        dict: A dictionary containing the status and a list of compartments if successful.
        str: An error message if the operation fails.
    """
    if not identity_client:
        return {"status": "error", "message": "OCI not configured. Please run configure_oci first."}
    
    try:
        response = identity_client.list_compartments(
            compartment_id=tenancy_id,
            compartment_id_in_subtree=True
        )
        
        compartments = []
        for compartment in response.data:
            compartments.append({
                "id": compartment.id,
                "name": compartment.name,
                "description": compartment.description,
                "lifecycle_state": compartment.lifecycle_state
            })
        
        return {"status": "success", "compartments": compartments}
    except Exception as e:
        return f"Error listing compartments: {str(e)}"

@mcp.tool()
def list_availability_domains(compartment_id: str):
    """
    List availability domains in a compartment.

    Args:
        compartment_id (str): The OCID of the compartment.
    
    Returns:
        dict: A dictionary containing the status and a list of availability domains if successful.
        str: An error message if the operation fails.
    """
    if not identity_client:
        return {"status": "error", "message": "OCI not configured. Please run configure_oci first."}
    
    try:
        response = identity_client.list_availability_domains(
            compartment_id=compartment_id
        )
        
        domains = []
        for domain in response.data:
            domains.append({
                "name": domain.name,
                "id": domain.id,
                "compartment_id": domain.compartment_id
            })
        
        return {"status": "success", "availability_domains": domains}
    except Exception as e:
        return f"Error listing availability domains: {str(e)}"


@mcp.tool()
def list_instances(compartment_id: str):
    """
    List all instances in a compartment with Instance ID, display name, lifecycle state, availability domain, shape, and time created.

    Args:
        compartment_id (str): The OCID of the compartment.
    
    Returns:
        dict: A dictionary containing the status and a list of instances if successful.
        str: An error message if the operation fails.
    """
    if not compute_client:
        return {"status": "error", "message": "OCI not configured. Please run configure_oci first."}
    
    try:
        response = compute_client.list_instances(
            compartment_id=compartment_id
        )
        
        instances = []
        for instance in response.data:
            instances.append({
                "id": instance.id,
                "display_name": instance.display_name,
                "lifecycle_state": instance.lifecycle_state,
                "availability_domain": instance.availability_domain,
                "shape": instance.shape,
                "time_created": instance.time_created.isoformat()
            })
        
        return {"status": "success", "instances": instances}
    except Exception as e:
        return f"Error listing instances: {str(e)}"



def get_instance(instance_id: str):
    """Get details of a specific instance using its Instance ID"""
    if not compute_client:
        return {"status": "error", "message": "OCI not configured. Please run configure_oci first."}
    
    try:
        response = compute_client.get_instance(instance_id=instance_id)
        instance = response.data
        # Try to get OCPU and memory info from shape_config or instance
        ocpus = None
        memory_in_gbs = None
        if hasattr(instance, "shape_config") and instance.shape_config:
            ocpus = getattr(instance.shape_config, "ocpus", None)
            memory_in_gbs = getattr(instance.shape_config, "memory_in_gbs", None)
        elif hasattr(instance, "ocpus"):
            ocpus = getattr(instance, "ocpus", None)
        elif hasattr(instance, "memory_in_gbs"):
            memory_in_gbs = getattr(instance, "memory_in_gbs", None)
        # Try to get instance agent id
        agent_id = getattr(instance, "instance_agent_id", None)
        instance_info = {
            "id": instance.id,
            "display_name": instance.display_name,
            "lifecycle_state": instance.lifecycle_state,
            "availability_domain": instance.availability_domain,
            "compartment_id": instance.compartment_id,
            "shape": instance.shape,
            "region": instance.region,
            "time_created": instance.time_created.isoformat(),
            "image_id": instance.image_id if hasattr(instance, 'image_id') else None,
            "metadata": instance.metadata if hasattr(instance, 'metadata') else {},
            "ocpus": ocpus,
            "memory_in_gbs": memory_in_gbs,
            "instance_agent_id": agent_id
        }
        return {"status": "success", "instance": instance_info}
    except Exception as e:
        return f"Error getting instance: {str(e)}"



@mcp.tool()
def get_compartment_id_by_name(name: str):
    """
    Get the OCID of a compartment by its name.

    Args:
        name (str): The name of the compartment.
    
    Returns:
        dict: A dictionary containing the status and compartment ID if successful.
        str: An error message if the operation fails.
    """
    if not identity_client:
        return {"status": "error", "message": "OCI not configured. Please run configure_oci first."}
    try:
        response = identity_client.list_compartments(
            compartment_id=tenancy_id,
            compartment_id_in_subtree=True
        )
        for compartment in response.data:
            if compartment.name == name:
                return {"status": "success", "compartment_id": compartment.id}
        return {"status": "error", "message": f"Compartment with name '{name}' not found."}
    except Exception as e:
        return f"Error searching for compartment: {str(e)}"


@mcp.tool()
def get_image_id_by_name(compartment_id: str, display_name: str, operating_system: Optional[str] = None):
    """
    Get the OCID of an image by its display name in a compartment (case-insensitive, trimmed, substring match).

    Args:
        compartment_id (str): The OCID of the compartment.
        display_name (str): The display name of the image.
        operating_system (str, optional): The operating system to filter images.
    
    Returns:
        dict: A dictionary containing the status and image ID if successful.
        str: An error message if the operation fails.
    """
    if not compute_client:
        return {"status": "error", "message": "OCI not configured. Please run configure_oci first."}
    try:
        list_args = {"compartment_id": compartment_id}
        if operating_system:
            list_args["operating_system"] = operating_system
        
        response = compute_client.list_images(**list_args)
        normalized_input = display_name.strip().lower()
        # First, try exact match
        for image in response.data:
            if image.display_name and image.display_name.strip().lower() == normalized_input:
                return {"status": "success", "image_id": image.id}
        # If not found, try substring match
        for image in response.data:
            if image.display_name and normalized_input in image.display_name.strip().lower():
                return {"status": "success", "image_id": image.id}
        # If still not found, return available image names for guidance
        available_images = [img.display_name for img in response.data if img.display_name]
        return {
            "status": "error",
            "message": f"Image with display name containing '{display_name}' not found.",
            "available_images": available_images
        }
    except Exception as e:
        return f"Error searching for image: {str(e)}"


@mcp.tool()
def get_instances_by_display_name(compartment_id: str, display_name: str):
    """
    Return all instances in a compartment whose display name matches the given substring (case-insensitive), with full details.

    Args:
        compartment_id (str): The OCID of the compartment.
        display_name (str): The display name substring to match.
    
    Returns:
        dict: A dictionary containing the status and a list of matching instances if successful.
        str: An error message if the operation fails.
    """
    if not compute_client:
        return {"status": "error", "message": "OCI not configured. Please run configure_oci first."}
    try:
        response = compute_client.list_instances(compartment_id=compartment_id)
        normalized_input = display_name.strip().lower()
        matches = []
        for instance in response.data:
            if instance.display_name and normalized_input in instance.display_name.strip().lower():
                # Try to get OCPU and memory info from shape_config or instance
                ocpus = None
                memory_in_gbs = None
                if hasattr(instance, "shape_config") and instance.shape_config:
                    ocpus = getattr(instance.shape_config, "ocpus", None)
                    memory_in_gbs = getattr(instance.shape_config, "memory_in_gbs", None)
                elif hasattr(instance, "ocpus"):
                    ocpus = getattr(instance, "ocpus", None)
                elif hasattr(instance, "memory_in_gbs"):
                    memory_in_gbs = getattr(instance, "memory_in_gbs", None)
                agent_id = getattr(instance, "instance_agent_id", None)
                matches.append({
                    "id": instance.id,
                    "display_name": instance.display_name,
                    "lifecycle_state": instance.lifecycle_state,
                    "availability_domain": instance.availability_domain,
                    "compartment_id": instance.compartment_id,
                    "shape": instance.shape,
                    "region": instance.region,
                    "time_created": instance.time_created.isoformat(),
                    "image_id": instance.image_id if hasattr(instance, 'image_id') else None,
                    "metadata": instance.metadata if hasattr(instance, 'metadata') else {},
                    "ocpus": ocpus,
                    "memory_in_gbs": memory_in_gbs,
                    "instance_agent_id": agent_id
                })
        if matches:
            return {"status": "success", "instances": matches}
        else:
            available_names = [inst.display_name for inst in response.data if inst.display_name]
            return {
                "status": "error",
                "message": f"No instances found with display name containing '{display_name}'.",
                "available_instance_names": available_names
            }
    except Exception as e:
        return f"Error searching for instances: {str(e)}"


@mcp.tool()
def create_tag_namespace(compartment_id: str, name: str, description: str = None):
    """
    Create a new tag namespace in the specified compartment.

    Args:
        compartment_id (str): The OCID of the compartment.
        name (str): The name of the tag namespace.
        description (str): Optional description.

    Returns:
        dict: Status and details.
    """
    try:
        details = oci.identity.models.CreateTagNamespaceDetails(
            compartment_id=compartment_id,
            name=name,
            description=description
        )
        response = identity_client.create_tag_namespace(details)
        return {"status": "success", "tag_namespace_id": response.data.id, "name": response.data.name}
    except Exception as e:
        return f"Error creating tag namespace: {str(e)}"


@mcp.tool()
def get_tag_namespace_by_name(compartment_id: str, name: str):
    """
    Get tag namespace by name in the specified compartment.

    Args:
        compartment_id (str): The OCID of the compartment.
        name (str): The name of the tag namespace.

    Returns:
        dict: Status and details.
    """
    try:
        response = identity_client.list_tag_namespaces(compartment_id=compartment_id)
        for ns in response.data:
            if ns.name == name:
                return {"status": "success", "tag_namespace_id": ns.id, "name": ns.name, "description": ns.description}
        return {"status": "error", "message": f"Tag namespace '{name}' not found in compartment {compartment_id}"}
    except Exception as e:
        return f"Error getting tag namespace: {str(e)}"


@mcp.tool()
def create_tag_name(tag_namespace_id: str, name: str, description: str = None):
    """
    Create a new tag in the specified tag namespace.

    Args:
        tag_namespace_id (str): The OCID of the tag namespace.
        name (str): The name of the tag.
        description (str): Optional description.

    Returns:
        dict: Status and details.
    """
    try:
        details = oci.identity.models.CreateTagDetails(
            name=name,
            description=description
        )
        response = identity_client.create_tag(tag_namespace_id, details)
        return {"status": "success", "tag_id": response.data.id, "name": response.data.name}
    except Exception as e:
        return f"Error creating tag: {str(e)}"


@mcp.tool()
def get_tags_by_name(tag_namespace_id: str, name: str):
    """
    Get tag by name in the specified tag namespace.

    Args:
        tag_namespace_id (str): The OCID of the tag namespace.
        name (str): The name of the tag.

    Returns:
        dict: Status and details.
    """
    try:
        response = identity_client.list_tags(tag_namespace_id)
        for tag in response.data:
            if tag.name == name:
                return {"status": "success", "tag_id": tag.id, "name": tag.name, "description": tag.description}
        return {"status": "error", "message": f"Tag '{name}' not found in namespace {tag_namespace_id}"}
    except Exception as e:
        return f"Error getting tag: {str(e)}"


@mcp.tool()
def assign_tag_name(instance_id: str, tag_namespace: str, tag_name: str, tag_value: str):
    """
    Assign a defined tag to an instance.

    Args:
        instance_id (str): The OCID of the instance.
        tag_namespace (str): The tag namespace name.
        tag_name (str): The tag name.
        tag_value (str): The tag value.

    Returns:
        dict: Status and details.
    """
    try:
        # Get the current instance to preserve other tags
        response = compute_client.get_instance(instance_id)
        current_defined_tags = response.data.defined_tags or {}
        # Add the new tag
        if tag_namespace not in current_defined_tags:
            current_defined_tags[tag_namespace] = {}
        current_defined_tags[tag_namespace][tag_name] = tag_value
        update_details = oci.core.models.UpdateInstanceDetails(
            defined_tags=current_defined_tags
        )
        compute_client.update_instance(instance_id, update_details)
        return {"status": "success", "message": f"Tag {tag_namespace}.{tag_name}={tag_value} assigned to instance {instance_id}"}
    except Exception as e:
        return f"Error assigning tag: {str(e)}"


@mcp.tool()
def get_assigned_tag_names(instance_id: str):
    """
    Get all assigned tags (defined and freeform) for an instance.

    Args:
        instance_id (str): The OCID of the instance.

    Returns:
        dict: Status and details.
    """
    try:
        response = compute_client.get_instance(instance_id)
        defined_tags = response.data.defined_tags or {}
        freeform_tags = response.data.freeform_tags or {}
        return {"status": "success", "defined_tags": defined_tags, "freeform_tags": freeform_tags}
    except Exception as e:
        return f"Error getting assigned tags: {str(e)}"


@mcp.tool()
def list_tag_namespaces(compartment_id: str):
    """
    List all tag namespaces in the specified compartment.

    Args:
        compartment_id (str): The OCID of the compartment.

    Returns:
        dict: Status and list of tag namespaces.
    """
    try:
        response = identity_client.list_tag_namespaces(compartment_id=compartment_id)
        namespaces = []
        for ns in response.data:
            namespaces.append({
                "id": ns.id,
                "name": ns.name,
                "description": ns.description,
                "time_created": ns.time_created.isoformat() if hasattr(ns, 'time_created') else None
            })
        return {"status": "success", "tag_namespaces": namespaces}
    except Exception as e:
        return f"Error listing tag namespaces: {str(e)}"


@mcp.tool()
def cve_to_elsa(
    compartment_id: str,
    instance_id: str
):
    """
    USE THIS TOOL WHEN:
    - User asks to "patch", "remediate", "fix vulnerabilities" on an instance
    - User asks "generate a patch script" for an instance

    WHAT IT DOES (fully internal — LLM never sees CVE list):
    1. Fetches ALL CVEs from the latest VSS vulnerability scan
    2. Fetches ALL SECURITY advisories from OSMH
    3. Matches CVEs -> ELSA advisories
    4. Returns patch command + unmatched CVEs

    LLM INSTRUCTIONS FOR BASH SCRIPT:
    - Use patch_command to build the yum update command
    - Add unmatched_cve_ids as comments (# No ELSA patch available)
    - If requires_reboot is true, append "sudo reboot" at end of script

    Args:
        compartment_id (str): OCID of the compartment the instance belongs to.
        instance_id (str): OCID of the instance (used for both VSS and OSMH).

    Returns:
        dict: {
            scan_id,
            total_cves_in_scan,
            total_matched,
            total_unmatched,
            all_elsa_advisories: ["ELSA-XXXX", ...],
            unmatched_cve_ids: ["CVE-XXXX", ...],
            requires_reboot: true/false,
            patch_command: "sudo yum update --advisory ELSA-XXXX ... -y"
        }
    """
    try:
        # Step 1: Fetch ALL CVEs from latest VSS scan
        list_resp = vulnerability_scanning_client.list_host_agent_scan_results(
            compartment_id=compartment_id,
            instance_id=instance_id,
            sort_order="ASC",
            is_latest_only=True
        )

        if not list_resp.data.items:
            return {"status": "error", "message": "No vulnerability scan results found."}

        scan_id   = list_resp.data.items[0].id
        scan_resp = vulnerability_scanning_client.get_host_agent_scan_result(
            host_agent_scan_result_id=scan_id
        )

        problems = scan_resp.data.problems or []

        seen     = set()
        cve_list = []
        for p in problems:
            if p.cve_reference and p.cve_reference not in seen:
                seen.add(p.cve_reference)
                cve_list.append(p.cve_reference.upper())

        if not cve_list:
            return {"status": "success", "message": "No CVEs found in scan.", "scan_id": scan_id}

        # Step 2: Fetch ALL SECURITY errata from OSMH
        all_errata = []
        next_page  = None

        while True:
            kwargs = {
                "managed_instance_id": instance_id,
                "classification_type": ["SECURITY"],
                "limit": 100,
            }
            if next_page:
                kwargs["page"] = next_page

            resp = osmh_client.list_managed_instance_errata(**kwargs)
            all_errata.extend(resp.data.items or [])
            next_page = resp.headers.get("opc-next-page")
            if not next_page:
                break

        if not all_errata:
            return {
                "status": "error",
                "message": (
                    "No OSMH SECURITY advisories found. "
                    "Verify instance_id is the OSMH managed instance OCID."
                )
            }

        # Step 3: Build reverse index CVE -> [ELSA, ...] for O(1) lookup
        cve_elsa_index = {}
        for e in all_errata:
            for cve in (e.related_cves or []):
                cve_upper = cve.upper()
                if cve_upper not in cve_elsa_index:
                    cve_elsa_index[cve_upper] = []
                cve_elsa_index[cve_upper].append(e.name)

        # Step 4: Match CVEs -> ELSA
        all_elsa      = set()
        all_unmatched = []

        for cve in cve_list:
            matched = cve_elsa_index.get(cve, [])
            if matched:
                all_elsa.update(matched)
            else:
                all_unmatched.append(cve)

        # Step 5: Detect reboot requirement (kernel advisory)
        matched_errata  = [e for e in all_errata if e.name in all_elsa]
        requires_reboot = any(
            "kernel" in (getattr(e, "synopsis", "") or "").lower() or
            any("kernel" in (getattr(p, "name", "") or "").lower()
                for p in (getattr(e, "packages", None) or []))
            for e in matched_errata
        )

        sorted_elsa   = sorted(all_elsa)
        advisory_args = " ".join(f"--advisory {e}" for e in sorted_elsa)

        return {
            "status": "success",
            "scan_id": scan_id,
            "total_cves_in_scan": len(cve_list),
            "total_matched": len(cve_list) - len(all_unmatched),
            "total_unmatched": len(all_unmatched),
            "all_elsa_advisories": sorted_elsa,
            "unmatched_cve_ids": all_unmatched,
            "requires_reboot": requires_reboot,
            "patch_command": f"sudo yum update {advisory_args} -y" if sorted_elsa else None,
        }

    except oci.exceptions.ServiceError as e:
        return {"status": "error", "message": str(e)}


@mcp.tool()
def remediate_vulnerabilities(compartment_id: str, instance_id: str, remediation_script: str):
    """
    Executes a bash remediation script on an OCI instance via the Run Command functionality.
    
    Args:
        compartment_id (str): The OCID of the compartment.
        instance_id (str): The OCID of the instance to run the script on.
        remediation_script (str): The bash script to run for remediation.
    
    Returns:
        dict: Contains the status and command ID of the executed command.
        str: Error message if execution fails.
    """

    try:
        print("Submitting Run Command...")

        # Prepare the command details
        command_details = oci.compute_instance_agent.models.CreateInstanceAgentCommandDetails(
            compartment_id=compartment_id,
            display_name="VulnerabilityRemediation",
            execution_time_out_in_seconds=7200,
            target=oci.compute_instance_agent.models.InstanceAgentCommandTarget(
                instance_id=instance_id
            ),
            content=oci.compute_instance_agent.models.InstanceAgentCommandContent(
                source=oci.compute_instance_agent.models.InstanceAgentCommandSourceViaTextDetails(
                    source_type="TEXT",
                    text=remediation_script
                )
            )
        )

        # Submit the command
        response = compute_instance_agent_client.create_instance_agent_command(
            create_instance_agent_command_details=command_details
        )

        command_id = response.data.id
        print(f"Command submitted. Command ID: {command_id}")

        # Poll until completion by using get_instance_agent_command_execution
        while True:
            # Fetch command execution status
            command_execution = compute_instance_agent_client.get_instance_agent_command_execution(
                instance_agent_command_id=command_id, instance_id=instance_id
            ).data

            status = command_execution.lifecycle_state  # Status of the command execution
            print("Current Status:", status)

            if status in ["IN_PROGRESS", "SUCCEEDED", "ACCEPTED", "FAILED", "CANCELED"]:
                break

            time.sleep(5)

        # Return final results
        return {
            "status": status,
            "command_id": command_id
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
    

@mcp.tool()
def email_notification(
    recipient: str,
    instance_name: str,
    instance_id: str,
    compartment_id: str,
    alarm_type: str,
    message: str
):
    """
    Send an email notification. The AI agent generates the message body.
    This tool ONLY sends an email — it does NOT determine content.

    Args:
        recipient (str): Email address to notify.
        instance_name (str): Name of the OCI instance.
        instance_id (str): Instance OCID.
        compartment_id (str): Compartment OCID.
        alarm_type (str): Type of alarm (e.g., Backup, Failure, Reboot).
        message (str): The full AI-generated content of the email.

    Returns:
        dict: Email send status.
    """

    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_SENDER = os.getenv("SMTP_SENDER")
    SMTP_USERNAME = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

    if not all([SMTP_HOST, SMTP_SENDER, SMTP_USERNAME, SMTP_PASSWORD]):
        return {
            "status": "error",
            "message": "Missing SMTP configuration. Ensure SMTP_HOST, SMTP_SENDER, SMTP_USERNAME, SMTP_PASSWORD are set."
        }

    # Subject line includes alarm type — stable and non-AI
    subject = f"{alarm_type} Alert for {instance_name}"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_SENDER
    msg["To"] = recipient

    # AI-generated message is appended below instance metadata
    msg.set_content(
        f"Alarm Type: {alarm_type}\n"
        f"Instance Name: {instance_name}\n"
        f"Instance ID: {instance_id}\n"
        f"Compartment ID: {compartment_id}\n\n"
        f"{message}"
    )

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)

        return {
            "status": "success",
            "email_status": "sent",
            "recipient": recipient,
            "instance_name": instance_name,
            "instance_id": instance_id,
            "compartment_id": compartment_id,
            "alarm_type": alarm_type
        }

    except Exception as e:
        return {
            "status": "error",
            "email_status": "failed",
            "message": str(e)
        }

@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    return JSONResponse({"status": "healthy", "service": "oci-instance-mcp-server"})


@mcp.custom_route("/ready", methods=["GET"])
async def readiness_check(request):
    return JSONResponse({"status": "healthy", "service": "oci-instance-mcp-server"})

def main() -> None:
    mcp.run(transport="streamable-http", port=8080, host="0.0.0.0")


if __name__ == "__main__":
    main()
