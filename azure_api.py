from azure.identity import ClientSecretCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from msal import ConfidentialClientApplication
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient
from azure.mgmt.sql import SqlManagementClient
from azure.keyvault.keys import KeyClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ManagementLockClient
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

import json
import requests

# AWS 자격 증명을 별도의 파일에서 읽어오기
def load_azure_credentials(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

class AZUREAPI:
    def __init__(self, credentials_file):
        credentials = load_azure_credentials(credentials_file)
        self.credential = ClientSecretCredential(client_id=credentials['client_id'], client_secret=credentials['client_secret'], tenant_id=credentials['tenant_id'])
        self.subscription_id = credentials['subscription_id']
        # az role assignment create --assignee {client_id} --role "Contributor" --scope "/subscriptions/{subscriptions_id}"
        self.auth_client = AuthorizationManagementClient(self.credential, self.subscription_id)
        self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
        self.compute_client = ComputeManagementClient(self.credential, self.subscription_id)
        self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
        self.network_client = NetworkManagementClient(self.credential, self.subscription_id)
        self.storage_client = StorageManagementClient(self.credential, self.subscription_id)
        self.keyvault_client = KeyVaultManagementClient(self.credential, self.subscription_id)
        self.sql_client = SqlManagementClient(self.credential, self.subscription_id)
        self.monitor_client = MonitorManagementClient(self.credential, self.subscription_id)
        self.lock_client = ManagementLockClient(self.credential, self.subscription_id)
        self.recovery_services_client = RecoveryServicesClient(self.credential, self.subscription_id)
        self.backup_client = RecoveryServicesBackupClient(self.credential, self.subscription_id)
        self.scope = ["https://graph.microsoft.com/.default"]
        # MSAL 설정 (authority 키워드 수정)
        self.app = ConfidentialClientApplication(
            client_id=credentials['client_id'],
            client_credential=credentials['client_secret'],
            authority=f"https://login.microsoftonline.com/{credentials['tenant_id']}"
        )
        self.token = self.get_token()
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def get_token(self):
        # 토큰 요청
        result = self.app.acquire_token_for_client(scopes=self.scope)
        if "access_token" in result:
            return result["access_token"]
        else:
            raise Exception("Failed to acquire token: " + json.dumps(result))

    def get_all_users(self):
        # Microsoft Graph API로 모든 사용자 가져오기
        endpoint = "https://graph.microsoft.com/v1.0/users"
        response = requests.get(endpoint, headers=self.headers)
        if response.status_code == 200:
            return response.json().get("value", [])
        else:
            raise Exception(f"Failed to fetch users: {response.status_code} {response.text}")
        
    def get_all_groups(self):
        # Microsoft Graph API로 모든 그룹 가져오기
        endpoint = "https://graph.microsoft.com/v1.0/groups"
        response = requests.get(endpoint, headers=self.headers)
        if response.status_code == 200:
            return response.json().get("value", [])
        else:
            raise Exception(f"Failed to fetch groups: {response.status_code} {response.text}")
        
    def get_group_owners(self, group_id):
        # 그룹의 소유자 가져오기
        endpoint = f"https://graph.microsoft.com/v1.0/groups/{group_id}/owners"
        response = requests.get(endpoint, headers=self.headers)
        if response.status_code == 200:
            return response.json().get("value", [])
        else:
            raise Exception(f"Failed to fetch group owners for {group_id}: {response.status_code} {response.text}")

    def get_group_members(self, group_id):
        # 그룹의 구성원 가져오기
        endpoint = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members"
        response = requests.get(endpoint, headers=self.headers)
        if response.status_code == 200:
            return response.json().get("value", [])
        else:
            raise Exception(f"Failed to fetch group members for {group_id}: {response.status_code} {response.text}")
        
    def get_password_reset_properties(self):
        # Microsoft Graph API로 암호 재설정 속성 가져오기
        endpoint = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
        response = requests.get(endpoint, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to fetch password reset properties: {response.status_code} {response.text}")

    def get_notifications_settings(self):
        # Microsoft Graph API로 암호 재설정 알림 설정 가져오기
        endpoint = "https://graph.microsoft.com/v1.0/policies/passwordResetPolicy"
        response = requests.get(endpoint, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to fetch password reset notifications: {response.status_code} {response.text}")

    def get_authentication_methods(self):
        # Microsoft Graph API로 인증 방법 가져오기
        endpoint = "https://graph.microsoft.com/v1.0/authenticationMethodsPolicy/authenticationMethodConfigurations"
        response = requests.get(endpoint, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to fetch authentication methods: {response.status_code} {response.text}")

    def evaluate_result(self, evidence, weak_message, success_message):
        if evidence:
            return {"weak": True, "message": weak_message, "evidence": evidence}
        return {"weak": False, "message": success_message, "evidence": ""}
    
    def get_role_assignments_ssh_key(self, resource_id):
        """
        특정 리소스(SSH Key)에 대한 역할 할당 확인
        """
        assignments = self.auth_client.role_assignments.list_for_scope(resource_id)
        role_assignments = []
        for assignment in assignments:
            role_assignments.append({
                "PrincipalId": assignment.principal_id,
                "RoleDefinitionId": assignment.role_definition_id,
                "Scope": assignment.scope
            })
        return role_assignments

    def get_role_definition(self, role_definition_id):
        """
        역할 정의 정보 가져오기
        """
        try:
            # 역할 정의 ID 추출
            role_id = role_definition_id.split("/")[-1]  # ID만 추출
            scope = f"/subscriptions/{self.subscription_id}"  # 구독 범위 설정

            # 역할 정의 가져오기
            role_definition = self.auth_client.role_definitions.get(scope=scope, role_definition_id=role_id)
            return role_definition
        except Exception as e:
            raise Exception(f"Failed to fetch role definition for {role_definition_id}: {str(e)}")
    
    def list_resource_groups(self):
        """
        구독 내 모든 리소스 그룹을 가져옵니다.
        """
        resource_groups = self.resource_client.resource_groups.list()
        return [rg.name for rg in resource_groups]

    def list_ssh_keys(self, resource_group_name):
        """
        특정 리소스 그룹에서 SSH 키 이름 가져오기
        """
        ssh_keys = self.resource_client.resources.list_by_resource_group(
            resource_group_name, 
            filter="resourceType eq 'Microsoft.Compute/sshPublicKeys'"
        )
        return [key.name for key in ssh_keys]
    
    def get_mfa_status(self, user_id):
        try:
            endpoint = f"https://graph.microsoft.com/v1.0/users/{user_id}/authentication/methods"
            response = requests.get(endpoint, headers=self.headers)
            if response.status_code == 200:
                methods = response.json().get("value", [])
                for method in methods:
                    if method.get("methodType") in ["phone", "app"]:
                        return True
                return False  # MFA 설정이 없는 경우
            else:
                raise Exception(f"Failed to fetch MFA methods: {response.status_code} {response.text}")
        except Exception as e:
            raise Exception(f"Failed to fetch MFA status for user {user_id}: {str(e)}")
        
    def get_authenticator_policy(self):
        try:
            endpoint = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
            response = requests.get(endpoint, headers=self.headers)
            if response.status_code == 200:
                policy = response.json()
                authenticator_config = next(
                    (method for method in policy.get("authenticationMethodConfigurations", [])
                     if method.get("id") == "MicrosoftAuthenticator"),
                    None
                )
                is_enabled = authenticator_config and authenticator_config.get("state") == "enabled"
                return {
                    "isEnabled": is_enabled,
                    "details": policy
                }
            raise Exception(f"Failed to fetch authentication policy: {response.status_code} {response.text}")
        except Exception as e:
            return {"error": str(e)}

    def get_password_protection_policy(self):
        try:
            endpoint = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
            response = requests.get(endpoint, headers=self.headers)

            if response.status_code == 200:
                policy = response.json()
                lockout_threshold = policy.get("lockoutThreshold", "Not Configured")
                lockout_duration = policy.get("lockoutDurationInSeconds", "Not Configured")

                is_configured = lockout_threshold != "Not Configured" and lockout_duration != "Not Configured"
                return {
                    "isConfigured": is_configured,
                    "lockoutThreshold": lockout_threshold,
                    "lockoutDurationInSeconds": lockout_duration
                }
            elif response.status_code == 403:
                return {"Issue": "Access Denied. This feature requires a Microsoft Entra ID Premium license."}
            else:
                raise Exception(f"Failed to fetch authorization policy: {response.status_code} {response.text}")
        except Exception as e:
            return {"error": str(e)}
        
    def get_password_reset_properties(self):
        endpoint = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
        response = requests.get(endpoint, headers=self.headers)
        if response.status_code == 200:
            policy = response.json ()
            registration_campaign = policy.get("registrationEnforcement", {}).get("authenticationMethodsRegistrationCampaign", {})
            return registration_campaign.get("state") == "enabled" or registration_campaign.get("state") == "default"
        else:
            raise Exception(f"Failed to fetch password reset properties: {response.status_code} {response.text}")

    def get_notifications_settings(self):
        endpoint = "https://graph.microsoft.com/v1.0/policies/passwordResetPolicy"
        response = requests.get(endpoint, headers=self.headers)
        if response.status_code == 200:
            policy = response.json()

            # 알림 설정 확인
            notify_users = policy.get("notifyUsersOnPasswordReset", False)  # 사용자가 암호를 재설정할 때 알림 설정 여부
            notify_admins = policy.get("notifyAdminsOnReset", False)  # 관리자가 암호를 재설정할 때 알림 설정 여부

            return {
                "notifyUsersOnPasswordReset": notify_users,
                "notifyAdminsOnReset": notify_admins,
                "details": policy
            }
        else:
            # 정책이 존재하지 않을 경우 처리
            return None

    def get_authentication_methods(self):
        endpoint = "https://graph.microsoft.com/v1.0/authenticationMethodsPolicy"
        response = requests.get(endpoint, headers=self.headers)
        if response.status_code == 200:
            policy = response.json()
            configurations = policy.get("authenticationMethodConfigurations", [])

            # 각 인증 방법 상태를 확인
            auth_methods = {}
            for config in configurations:
                method_id = config.get("id")
                state = config.get("state")
                auth_methods[method_id] = {"isEnabled": state == "enabled", "details": config}
        
            return auth_methods
        else:
            return None
        
    def get_role_assignments(self):
        try:
            # 구독 전체의 역할 할당 가져오기
            scope = f"/subscriptions/{self.subscription_id}"
            role_assignments = list(self.auth_client.role_assignments.list_for_scope(scope))
            return role_assignments
        except Exception as e:
            raise Exception(f"Failed to fetch role assignments: {str(e)}")
        
    def get_resource_group_roles(self, resource_group_name):
        """
        특정 리소스 그룹에서 할당된 역할 가져오기
        """
        try:
            resource_scope = f"/subscriptions/{self.subscription_id}/resourceGroups/{resource_group_name}"
            assignments = self.auth_client.role_assignments.list_for_scope(resource_scope)

            roles = []
            for assignment in assignments:
                role_definition_id = assignment.role_definition_id
                principal_id = assignment.principal_id

                # 역할 정의 가져오기
                role_definition = self.get_role_definition(role_definition_id)
                if hasattr(role_definition, "role_name"):
                    role_name = role_definition.role_name
                else:
                    role_name = "Unknown"

                roles.append({
                    "PrincipalId": principal_id,
                    "RoleName": role_name,
                    "Scope": resource_scope
                })

            return roles
        except Exception as e:
            raise Exception(f"Failed to fetch roles for resource group {resource_group_name}: {str(e)}")
        
    def get_user_assigned_roles(self, user_id):
        # Microsoft Graph API로 특정 사용자의 할당된 역할 가져오기
        endpoint = f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf"
        response = requests.get(endpoint, headers=self.headers)
        if response.status_code == 200:
            roles = []
            for item in response.json().get("value", []):
                if item["@odata.type"] == "#microsoft.graph.directoryRole":
                    roles.append({
                        "roleName": item.get("displayName"),
                        "roleId": item.get("id")
                    })
            return roles
        else:
            raise Exception(f"Failed to fetch roles for user {user_id}: {response.status_code} {response.text}")
        
    def list_resources(self, resource_type):
        # List resources by type
        resources = []
        for rg in self.resource_client.resource_groups.list():
            resources.extend(
                self.resource_client.resources.list_by_resource_group(
                    resource_group_name=rg.name,
                    filter=f"resourceType eq '{resource_type}'"
                )
            )
        return resources

    def get_role_assignments_name(self, resource_id):
        # List IAM role assignments for a specific resource
        assignments = self.auth_client.role_assignments.list_for_scope(resource_id)
        role_details = []
        for assignment in assignments:
            role_name = self.get_role_definition_by_id(assignment.role_definition_id).role_name
            role_details.append({
                "PrincipalId": assignment.principal_id,
                "RoleName": role_name,
                "Scope": assignment.scope
            })
        return role_details
    
    def get_role_definition_by_id(self, role_definition_id):
        # Get role definition by ID
        return self.auth_client.role_definitions.get_by_id(role_definition_id)

        
    def get_public_ip_of_connected_devices(self, resource_group_name, virtual_network_name):
        try:
            # 가상 네트워크 정보 가져오기
            virtual_network = self.network_client.virtual_networks.get(
                resource_group_name, virtual_network_name
            )

            # 연결된 디바이스 확인
            connected_devices = {}
            for subnet in virtual_network.subnets:
                if subnet.name:
                    connected_devices.update({subnet.name: subnet.id})

            # print(f"connected_devices: {connected_devices}")
            public_ips = []

            for device_name, device_id in connected_devices.items():
                # 디바이스 ID에서 공용 IP를 검색
                public_ip_resources = self.network_client.public_ip_addresses.list(resource_group_name)
                for public_ip in public_ip_resources:
                    if public_ip.ip_configuration and public_ip.ip_configuration.id.startswith(device_id):
                        public_ips.append({
                            "device_name": device_name,
                            "device_id": device_id,
                            "public_ip": public_ip.ip_address
                        })

            return public_ips

        except Exception as e:
            print(f"Error occurred: {e}")
            return []
        
    def get_all_resource_groups(self):
        """
        모든 리소스 그룹 가져오기
        """
        try:
            return [rg.name for rg in self.resource_client.resource_groups.list()]
        except Exception as e:
            print(f"Error fetching resource groups: {e}")
            return []
        
    def get_vpn_gateway_configurations(self, resource_group_name, gateway_name):
        """
        가상 네트워크 게이트웨이의 지점 및 사이트 간 구성 확인
        """
        try:
            gateway = self.network_client.virtual_network_gateways.get(resource_group_name, gateway_name)
            connections = self.network_client.virtual_network_gateway_connections.list(resource_group_name)
            
            vpn_configurations = []
            for connection in connections:
                if connection.virtual_network_gateway1.id == gateway.id:
                    vpn_configurations.append({
                        "ConnectionName": connection.name,
                        "ConnectionType": connection.connection_type,
                        "SharedKey": connection.shared_key,
                        "RemoteNetwork": connection.remote_vpn_site
                    })
            
            return vpn_configurations
        except Exception as e:
            print(f"Error fetching VPN gateway configurations: {e}")
            return []
        
    def get_virtual_network_gateways(self, resource_group_name):
        """
        특정 리소스 그룹 내 모든 가상 네트워크 게이트웨이를 가져옵니다.
        """
        try:
            # 모든 리소스 중 가상 네트워크 게이트웨이만 필터링
            resources = self.resource_client.resources.list_by_resource_group(resource_group_name)
            gateways = [
                resource for resource in resources 
                if resource.type == "Microsoft.Network/virtualNetworkGateways"
            ]
            return gateways
        except Exception as e:
            print(f"Error fetching virtual network gateways for resource group {resource_group_name}: {e}")
            return []


    def check_bastion_connection(self, resource_group_name, vm_name):
        """
        가상 머신의 베스천 연결 확인
        """
        try:
            bastion_hosts = self.network_client.bastion_hosts.list_by_resource_group(resource_group_name)
            vm = self.compute_client.virtual_machines.get(resource_group_name, vm_name)
            
            bastion_connections = []
            for bastion in bastion_hosts:
                if vm.network_profile.network_interfaces:
                    for nic in vm.network_profile.network_interfaces:
                        if bastion.ip_configurations[0].public_ip_address:
                            bastion_connections.append({
                                "BastionName": bastion.name,
                                "PublicIP": bastion.ip_configurations[0].public_ip_address.id
                            })

            return bastion_connections
        except Exception as e:
            print(f"Error fetching Bastion connections: {e}")
            return []
        
    def get_network_security_groups(self):
        """
        모든 네트워크 보안 그룹 가져오기
        """
        try:
            nsgs = self.network_client.network_security_groups.list_all()
            return list(nsgs)
        except Exception as e:
            raise Exception(f"Failed to fetch network security groups: {str(e)}")

    def get_security_rules(self, resource_group_name, nsg_name):
        """
        특정 네트워크 보안 그룹의 보안 규칙 가져오기
        """
        try:
            nsg = self.network_client.network_security_groups.get(resource_group_name, nsg_name)
            return nsg.security_rules
        except Exception as e:
            raise Exception(f"Failed to fetch security rules for NSG {nsg_name}: {str(e)}")
        
    def get_firewall_policies(self):
        """
        모든 방화벽 정책 가져오기
        """
        try:
            firewall_policies = self.network_client.firewall_policies.list_all()
            return list(firewall_policies)
        except Exception as e:
            raise Exception(f"Failed to fetch firewall policies: {str(e)}")

    def get_firewall_policy_rule_collections(self, resource_group_name, policy_name):
        """
        방화벽 정책의 규칙 컬렉션 가져오기
        """
        try:
            rule_collections = self.network_client.firewall_policies.list_rule_collections(resource_group_name, policy_name)
            return list(rule_collections)
        except Exception as e:
            raise Exception(f"Failed to fetch rule collections for policy {policy_name}: {str(e)}")

    def get_firewalls(self):
        """
        모든 방화벽 가져오기
        """
        try:
            firewalls = self.network_client.azure_firewalls.list_all()
            return list(firewalls)
        except Exception as e:
            raise Exception(f"Failed to fetch firewalls: {str(e)}")

    def get_firewall_rules(self, resource_group_name, firewall_name):
        """
        방화벽의 규칙 컬렉션 가져오기
        """
        try:
            firewall = self.network_client.azure_firewalls.get(resource_group_name, firewall_name)
            return firewall.ip_configurations
        except Exception as e:
            raise Exception(f"Failed to fetch rules for firewall {firewall_name}: {str(e)}")
        
    def get_nat_gateways(self):
        """
        NAT 게이트웨이 리스트를 가져옵니다.
        """
        try:
            return list(self.network_client.nat_gateways.list_all())
        except Exception as e:
            raise Exception(f"Failed to fetch NAT Gateways: {str(e)}")

    def get_nat_gateway_subnets(self, resource_group_name, nat_gateway_name):
        """
        특정 NAT 게이트웨이에 연결된 서브넷을 가져옵니다.
        """
        try:
            nat_gateway = self.network_client.nat_gateways.get(resource_group_name, nat_gateway_name)
            return nat_gateway.subnets
        except Exception as e:
            raise Exception(f"Failed to fetch subnets for NAT Gateway {nat_gateway_name}: {str(e)}")
        
    def list_storage_accounts(self):
        """
        모든 스토리지 계정 가져오기기.
        """
        return self.storage_client.storage_accounts.list()
    
    def get_storage_properties_network_rule_set(self, resource_group_name, account_name):
        properties = self.storage_client.storage_accounts.get_properties(resource_group_name, account_name).network_rule_set

        return properties
    
    def get_blob_token(self, account_name):
        blob_service_client = BlobServiceClient(f"https://{account_name}.blob.core.windows.net", credential=self.credential)

        return blob_service_client
    
    def list_sql_servers(self):
        """
        모든 SQL 서버 가져오기기.
        """
        return self.sql_client.servers.list()
    
    def list_databases_by_server(self, resource_group_name, server_name):
        databases = self.sql_client.databases.list_by_server(resource_group_name, server_name)

        return databases
    
    def get_transparent_data_encryptions(self, resource_group_name, server_name, db_name):
        tde = self.sql_client.transparent_data_encryptions.get(resource_group_name, server_name, db_name)

        return tde
    
    def get_storage_properties(self, resource_group_name, account_name):
        encryption = self.storage_client.storage_accounts.get_properties(resource_group_name, account_name)

        return encryption
    
    def get_storage_properties_encryption(self, resource_group_name, account_name):
        encryption = self.storage_client.storage_accounts.get_properties(resource_group_name, account_name).encryption

        return encryption
    
    def list_storage_by_resource_group(self, rg):
        storage_accounts = self.storage_client.storage_accounts.list_by_resource_group(rg)

        return storage_accounts
    
    def list_disk_encryption_sets(self):
        disk_encryption_sets = self.compute_client.disk_encryption_sets.list()

        return disk_encryption_sets

    def list_computer_by_resource_group(self, rg):
        disks = self.compute_client.disks.list_by_resource_group(rg)

        return disks
    
    def list_resource_client_groups(self):
        """
        모든 가상 네트워크 게이트웨이 가져오기
        """
        return self.resource_client.resource_groups.list()
        
    def get_sql_client_servers(self, resource_group_name, name):
        properties = self.sql_client.servers.get(resource_group_name, name)

        return properties
    
    def list_network_client_virtual_network_gateways(self, rg_name):
        return self.network_client.virtual_network_gateways.list(rg_name)
    
    def list_keyvaults(self):
        """
        모든 키 자격 증명 모음을 가져옵니다.
        """
        try:
            return list(self.keyvault_client.vaults.list())
        except Exception as e:
            raise Exception(f"Failed to fetch key vaults: {str(e)}")

    def check_key_rotation_policy(self, vault_name, key_name):
        """
        특정 키의 회전 정책을 확인합니다.
        """
        try:
            key_client = KeyClient(vault_url=f"https://{vault_name}.vault.azure.net", credential=self.credential)
            rotation_policy = key_client.get_key_rotation_policy(key_name)
            if rotation_policy:
                for rule in rotation_policy.lifetime_actions:
                    if rule.action == "Rotate" and rule.trigger.time_after_create:
                        days = int(rule.trigger.time_after_create.strip("P").strip("D"))
                        return {"KeyName": key_name, "RotationDays": days}
            return {"KeyName": key_name, "RotationDays": "Not Set"}
        except Exception as e:
            return {"KeyName": key_name, "Error": str(e)}
        
    def list_keys_by_resgp_vn(self, resource_group, vault_name):
        return self.keyvault_client.keys.list(resource_group, vault_name)
    
    def get_diagnostic_settings(self, resource_id):
        """
        특정 리소스의 진단 설정 가져오기
        """
        try:
            settings = self.monitor_client.diagnostic_settings.list(resource_id)
            return list(settings)
        except Exception as e:
            raise Exception(f"Failed to fetch diagnostic settings for {resource_id}: {str(e)}")
        
    def list_resources(self):
        return self.resource_client.resources.list()
    
    def list_compute_virtual_machines(self, rg_name):
        vms = self.compute_client.virtual_machines.list(rg_name)
        
        return vms
    
    def list_client_resource_groups(self):
        return self.resource_client.resource_groups.list()
    
    def check_insights_registration(self, subscription_id):
        """
        Microsoft.Insights 리소스 공급자 등록 여부 확인
        """
        try:
            provider = self.resource_client.providers.get("Microsoft.Insights")
            if provider.registration_state != "Registered":
                return {
                    "Issue": "Microsoft.Insights is not registered",
                    "Resolution": f"Run 'az provider register --namespace Microsoft.Insights' for subscription {subscription_id}"
                }
        except Exception as e:
            return {"Issue": "Failed to check Microsoft.Insights registration", "Error": str(e)}
        return None
    
    def get_virtual_networks(self):
        """
        모든 가상 네트워크 가져오기
        """
        try:
            vnets = self.network_client.virtual_networks.list_all()
            return list(vnets)
        except Exception as e:
            print(f"Error fetching virtual networks: {str(e)}")
            return []
        
    def get_locks_for_resource_group(self, resource_group_name):
        """
        특정 리소스 그룹의 잠금 설정 확인
        """
        try:
            locks = self.lock_client.management_locks.list_at_resource_group_level(resource_group_name)
            return list(locks)
        except Exception as e:
            print(f"Error fetching locks for resource group {resource_group_name}: {e}")
            return []
        
    def list_recovery_vaults(self):
        """
        모든 Recovery Services Vaults 가져오기 (리소스 그룹별로 검색)
        """
        try:
            resource_groups = self.list_resource_client_groups()
            vaults = []
            for rg in resource_groups:
                vaults.extend(self.recovery_services_client.vaults.list_by_resource_group(rg.name))
            return vaults
        except Exception as e:
            print(f"Error fetching Recovery Services Vaults: {e}")
            return []

    def list_backup_policies(self, resource_group_name, vault_name):
        """
        특정 Vault 내 백업 정책 가져오기
        """
        try:
            return list(
                self.backup_client.protection_policies.list(
                    vault_name=vault_name,
                    resource_group_name=resource_group_name
                )
            )
        except Exception as e:
            print(f"Error fetching backup policies for vault {vault_name}: {e}")
            return []

    def list_protected_items(self, resource_group_name, vault_name):
        """
        특정 Vault 내 보호된 아이템(백업된 리소스) 가져오기
        """
        try:
            return list(
                self.backup_client.backup_protected_items.list(
                    vault_name=vault_name,
                    resource_group_name=resource_group_name
                )
            )
        except Exception as e:
            print(f"Error fetching protected items for vault {vault_name}: {e}")
            return []