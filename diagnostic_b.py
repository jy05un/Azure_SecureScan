from azure_api import AZUREAPI

class DiagnosticB:
    def __init__(self, credentials_file):
        self.azure_api = AZUREAPI(credentials_file)

    # 구독 액세스 제어 역할 관리 - 자동화
    # 완성
    def B01(self):
        evidence = []

        try:
            # 구독에 설정된 모든 역할 할당 가져오기
            role_assignments = self.azure_api.get_role_assignments()

            for assignment in role_assignments:
                role_definition_id = assignment.role_definition_id

                try:
                    # 역할 정의 가져오기
                    role_definition = self.azure_api.get_role_definition(role_definition_id)
                    role_name = role_definition.role_name if role_definition else "Unknown"

                    # Reader 역할인지 확인
                    if role_name != "Reader":
                        evidence.append({
                            "PrincipalId": assignment.principal_id,
                            "RoleName": role_name,
                            "Scope": assignment.scope
                        })
                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to fetch role definition for {role_definition_id}",
                        "Error": str(e)
                    })

        except Exception as e:
            return self.azure_api.evaluate_result([{"Issue": "Failed to fetch role assignments", "Error": str(e)}],
                                            "구독 액세스 제어 역할 관리가 미흡합니다.", "양호합니다.")

        return self.azure_api.evaluate_result(evidence, "구독 액세스 제어 역할 관리가 미흡합니다.", "양호합니다.")
    
    # 리소스 그룹 액세스 제어 역할 할당 - 자동화
    # 완성
    def B02(self):
        evidence = []
        privileged_roles = ["Owner", "Contributor", "User Access Administrator"]
        
        try:
            # 모든 리소스 그룹 가져오기
            resource_groups = self.azure_api.list_resource_groups()

            for resource_group in resource_groups:
                try:
                    # 각 리소스 그룹의 역할 가져오기
                    assigned_roles = self.azure_api.get_resource_group_roles(resource_group)
                    assigned_role_names = [role["RoleName"] for role in assigned_roles]

                    # 과도한 역할이 부여된 경우 확인
                    excessive_roles = [role for role in assigned_role_names if role in privileged_roles]
                    if excessive_roles:
                        evidence.append({
                            "ResourceGroup": resource_group,
                            "ExcessiveRoles": excessive_roles,
                            "AllAssignedRoles": assigned_role_names
                        })

                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to fetch roles for resource group {resource_group}",
                        "Error": str(e)
                    })

        except Exception as e:
            return self.azure_api.evaluate_result([{"Issue": "Failed to fetch resource groups", "Error": str(e)}],
                                            "리소스 그룹 역할 관리가 미흡합니다.", "양호합니다.")

        return self.azure_api.evaluate_result(evidence, "리소스 그룹별 액세스 제어 역할 할당에 확인이 필요합니다.", "양호합니다.")
    
    # AD 사용자 역할 권한 관리 - 자동화
    # 완성
    def B03(self):
        evidence = []
        privileged_roles = ["Global Administrator", "User Administrator", "Application Administrator"]

        try:
            # 모든 사용자 가져오기
            users = self.azure_api.get_all_users()

            for user in users:
                user_id = user.get("id")
                user_display_name = user.get("displayName", "Unknown")
                
                try:
                    # 사용자에 할당된 역할 가져오기
                    assigned_roles = self.azure_api.get_user_assigned_roles(user_id)
                    
                    # 민감한 역할 확인
                    for role in assigned_roles:
                        role_name = role.get("roleName", "Unknown Role")
                        
                        if role_name in privileged_roles:
                            evidence.append({
                                "UserId": user_id,
                                "DisplayName": user_display_name,
                                "RoleName": role_name,
                                "Details": role
                            })

                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to fetch roles for user {user_display_name} ({user_id})",
                        "Error": str(e)
                    })

        except Exception as e:
            return self.azure_api.evaluate_result(
                [{"Issue": "Failed to fetch users", "Error": str(e)}],
                "AD 관리 역할 관리가 미흡합니다.",
                "양호합니다."
            )

        return self.azure_api.evaluate_result(evidence, "AD 사용자 역할 권한 관리가 미흡합니다.", "양호합니다.")
    
    # 인스턴스 서비스 액세스 정책 관리 - 자동화
    # 완성
    def B04(self):
        evidence = []
    
        # Define the resource types to check
        resource_types = [
            "Microsoft.Compute/virtualMachines",
            "Microsoft.ContainerInstance/containerGroups",
            "Microsoft.ContainerService/managedClusters",
            "Microsoft.Storage/storageAccounts",
            "Microsoft.DataLakeStore/accounts",
            "Microsoft.DocumentDB/databaseAccounts",
            "Microsoft.Sql/servers",
            "Microsoft.DBforMySQL/servers",
            "Microsoft.DBforPostgreSQL/servers"
        ]

        for resource_type in resource_types:
            try:
                resources = self.azure_api.list_resources(resource_type)
                for resource in resources:
                    try:
                        role_assignments = self.azure_api.get_role_assignments_name(resource.id)
                        for assignment in role_assignments:
                            if assignment["RoleName"] in ["Owner", "Contributor"]:
                                evidence.append({
                                    "ResourceName": resource.name,
                                    "ResourceType": resource_type,
                                    "PrincipalId": assignment["PrincipalId"],
                                    "RoleName": assignment["RoleName"],
                                    "Scope": assignment["Scope"]
                                })
                    except Exception as e:
                        evidence.append({
                            "Issue": f"Failed to fetch roles for resource {resource.name}",
                            "Error": str(e)
                        })
            except Exception as e:
                evidence.append({
                    "Issue": f"Failed to list resources of type {resource_type}",
                    "Error": str(e)
                })

        return self.azure_api.evaluate_result(evidence, "일부 리소스에 대해 과도한 IAM 역할이 할당되어 있습니다.", "양호합니다.")

    # 네트워크 서비스 액세스 정책 관리 - 자동화
    # 완성
    def B05(self):
        evidence = []
    
        # Define the network service resource types to check
        network_resource_types = [
            "Microsoft.Network/virtualNetworks",
            "Microsoft.Cdn/profiles",
            "Microsoft.Network/privateLinkServices",
            "Microsoft.Network/networkSecurityGroups",
            "Microsoft.Network/publicIPAddresses",
            "Microsoft.Network/routeTables",
            "Microsoft.Network/dnsZones",
            "Microsoft.Network/natGateways",
            "Microsoft.Network/virtualNetworkGateways",
            "Microsoft.Network/applicationGateways"
        ]

        try:
            for resource_type in network_resource_types:
                try:
                    resources = self.azure_api.list_resources(resource_type)
                    for resource in resources:
                        try:
                            role_assignments = self.azure_api.get_role_assignments_name(resource.id)
                            for assignment in role_assignments:
                                if assignment["RoleName"] in ["Owner", "Contributor"]:
                                    evidence.append({
                                        "ResourceName": resource.name,
                                        "ResourceType": resource_type,
                                        "PrincipalId": assignment["PrincipalId"],
                                        "RoleName": assignment["RoleName"],
                                        "Scope": assignment["Scope"]
                                    })
                        except Exception as e:
                            evidence.append({
                                "Issue": f"Failed to fetch roles for resource {resource.name}",
                                "Error": str(e)
                            })
                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to list resources of type {resource_type}",
                        "Error": str(e)
                    })
        except Exception as e:
            return self.azure_api.evaluate_result(
                [{"Issue": "Failed to check network resource IAM roles", "Error": str(e)}],
                "네트워크 리소스 IAM 역할 관리가 미흡합니다.",
                "모든 네트워크 리소스의 IAM 역할이 적절하게 할당되었습니다."
            )

        return self.azure_api.evaluate_result(evidence, "네트워크 리소스 IAM 역할 관리가 미흡합니다.", "양호합니다.")
    
    # 기타 서비스 액세스 정책 관리 - 자동화
    # 완성
    def B06(self):
        evidence = []

        # Define resource types for miscellaneous services
        service_resource_types = [
            "Microsoft.Web/sites",  # App Services
            "Microsoft.DBforMySQL/servers",  # MySQL
            "Microsoft.DBforPostgreSQL/servers",  # PostgreSQL
            "Microsoft.Sql/servers",  # SQL Server
            "Microsoft.CosmosDB/databaseAccounts",  # Cosmos DB
            "Microsoft.Storage/storageAccounts",  # Storage Account
            "Microsoft.DataLakeStore/accounts",  # Data Lake Storage
            "Microsoft.Compute/virtualMachineScaleSets",  # Virtual Machine Scale Sets
            "Microsoft.Network/loadBalancers",  # Load Balancers
            "Microsoft.Network/azureFirewalls",  # Firewalls
            "Microsoft.Network/applicationGateways",  # WAF
            "Microsoft.DataLakeAnalytics/accounts",  # Data Lake Analytics
            "Microsoft.Web/serverFarms",  # App Service Plans
            "Microsoft.OperationalInsights/workspaces",  # Log Analytics
            "Microsoft.Security/pricings",  # Microsoft Defender for Cloud
            "Microsoft.ManagedIdentity/userAssignedIdentities",  # Managed Identities
            "Microsoft.KeyVault/vaults",  # Key Vaults
            "Microsoft.Insights/components",  # Monitor
            "Microsoft.AAD/identityProtection",  # AD Identity Protection
            "Microsoft.Insights/eventCategories",  # Activity Logs
            "Microsoft.RecoveryServices/vaults",  # Backup Center
            "Microsoft.Network/networkWatchers"  # Network Watcher
        ]

        privileged_roles = ["Owner", "Contributor", "User Access Administrator"]

        try:
            for resource_type in service_resource_types:
                try:
                    resources = self.azure_api.list_resources(resource_type)
                    for resource in resources:
                        try:
                            role_assignments = self.azure_api.get_role_assignments_name(resource.id)
                            for assignment in role_assignments:
                                if assignment["RoleName"] in privileged_roles:
                                    evidence.append({
                                        "ResourceName": resource.name,
                                        "ResourceType": resource_type,
                                        "PrincipalId": assignment["PrincipalId"],
                                        "RoleName": assignment["RoleName"],
                                        "Scope": assignment["Scope"]
                                    })
                        except Exception as e:
                            evidence.append({
                                "Issue": f"Failed to fetch roles for resource {resource.name}",
                                "Error": str(e)
                            })
                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to list resources of type {resource_type}",
                        "Error": str(e)
                    })
        except Exception as e:
            return self.azure_api.evaluate_result(
                [{"Issue": "Failed to check miscellaneous service IAM roles", "Error": str(e)}],
                "기타 서비스 IAM 역할 관리가 미흡합니다.",
                "모든 기타 서비스의 IAM 역할이 적절하게 할당되었습니다."
            )

        return self.azure_api.evaluate_result(evidence, "기타 서비스 IAM 역할 관리가 미흡합니다.", "양호합니다.")