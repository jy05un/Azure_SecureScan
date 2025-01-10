from azure_api import AZUREAPI

class DiagnosticD:
    def __init__(self, credentials_file):
        self.azure_api = AZUREAPI(credentials_file)

    # 데이터베이스 암호화 설정 관리 - 자동화
    # 완성 (재차 확인 필요)
    def D01(self):
        evidence = []
        # 투명한 데이터 암호화(TDE) 확인
        try:
            # 모든 스토리지 계정 가져오기
            sql_servers = self.azure_api.list_sql_servers()

            for server in sql_servers:
                server_name = server.name
                resource_group_name = server.id.split('/')[4]

                try:
                    # 서버에 연결된 데이터베이스 가져오기
                    databases = self.azure_api.list_databases_by_server(resource_group_name, server_name)
                    for db in databases:
                        db_name = db.name

                        # 투명한 데이터 암호화(TDE) 상태 확인
                        tde = self.azure_api.get_transparent_data_encryptions(resource_group_name, server_name, db_name)
                        if tde.status != "Enabled":
                            evidence.append({
                                    "ServerName": server_name,
                                    "DatabaseName": db_name,
                                    "EncryptionStatus": tde.status
                                })
                except Exception as e:
                        evidence.append({
                            "Issue": f"Failed to fetch encryption details for server {server_name}",
                            "Error": str(e)
                        })
        
        except Exception as e:
                evidence.append({
                    "Issue": "Failed to fetch SQL servers",
                    "Error": str(e)
                })

        # 데이터 암호화 기능 확인
        try:
            # 모든 스토리지 계정 가져오기
            storage_accounts = self.azure_api.list_storage_accounts()

            for account in storage_accounts:
                account_name = account.name
                resource_group_name = account.id.split('/')[4]

                try:
                    # 스토리지 계정의 암호화 설정 가져오기
                    encryption = self.azure_api.get_storage_properties_encryption(resource_group_name, account_name)

                    if not encryption.services.blob.enabled or not encryption.services.file.enabled:
                        evidence.append({
                                "StorageAccount": account_name,
                                "ResourceGroup": resource_group_name,
                                "BlobEncryptionEnabled": encryption.services.blob.enabled,
                                "FileEncryptionEnabled": encryption.services.file.enabled
                            })
                except Exception as e:
                        evidence.append({
                            "Issue": f"Failed to fetch encryption details for storage account {account_name}",
                            "Error": str(e)
                        })

        except Exception as e:
                evidence.append({
                    "Issue": "Failed to fetch storage accounts",
                    "Error": str(e)
                })

        return self.azure_api.evaluate_result(evidence, "SQL 데이터베이스 또는 스토리지 계정의 암호화 설정이 미흡합니다.", "양호합니다.")
    
    # 스토리지 암호화 설정 - 자동화
    # 완성
    def D02(self):
        evidence = []

        try:
            resource_groups = self.azure_api.get_all_resource_groups()

            for rg in resource_groups:
                storage_accounts = self.azure_api.list_storage_by_resource_group(rg)

                for account in storage_accounts:
                    try:
                        properties = self.azure_api.storage_client.storage_accounts.get_properties(rg, account.name)
                        encryption = properties.encryption
                        encryption_type = encryption.key_source

                        if encryption_type == "Microsoft.Keyvault":
                            # 사용자 관리형 키
                            evidence.append({
                                "StorageAccount": account.name,
                                "ResourceGroup": rg,
                                "KeySource": "Customer-Managed Key (Microsoft.Keyvault)",
                                "KeyVaultUri": encryption.key_vault_properties.key_vault_uri if encryption.key_vault_properties else "Unknown"
                            })
                        elif encryption_type == "Microsoft.Storage":
                            # 플랫폼 관리형 키
                            evidence.append({
                                "StorageAccount": account.name,
                                "ResourceGroup": rg,
                                "KeySource": "Platform-Managed Key (Microsoft.Storage)"
                            })
                        else:
                            # 설정되지 않음
                            evidence.append({
                                "StorageAccount": account.name,
                                "ResourceGroup": rg,
                                "KeySource": "Unknown or Not Configured"
                            })
                    except Exception as e:
                        evidence.append({
                            "Issue": f"Failed to fetch encryption details for storage account {account.name}",
                            "Error": str(e)
                        })

        except Exception as e:
                evidence.append({
                    "Issue": "Failed to fetch storage accounts or resource groups",
                    "Error": str(e)
                })

        return self.azure_api.evaluate_result(evidence, "스토리지 암호화 설정이 미흡합니다.", "양호합니다.")

    # 디스크 암호화 설정
    # 완성
    def D03(self):
        evidence = []

        # 디스크 암호화 집합의 암호화 설정 확인
        try:
            disk_encryption_sets = self.azure_api.list_disk_encryption_sets()

            for des in disk_encryption_sets:
                try:
                    encryption_type = des.encryption_type
                    key_value = des.active_key.key_url if des.active_key else "N/A"

                    if encryption_type == "EncryptionAtRestWithCustomerKey":
                        evidence.append({
                            "DiskEncryptionSet": des.name,
                            "EncryptionType": "Customer-Managed Key (Key Vault)",
                            "KeyVaultURL": key_vault
                        })
                    elif encryption_type == "EncryptionAtRestWithPlatformKey":
                        evidence.append({
                            "DiskEncryptionSet": des.name,
                            "EncryptionType": "Platform-Managed Key"
                        })
                    else:
                        evidence.append({
                            "DiskEncryptionSet": des.name,
                            "EncryptionType": "Unknown or Not Configured"
                        })
                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to fetch encryption details for Disk Encryption Set {des.name}",
                        "Error": str(e)
                    })
        except Exception as e:
            evidence.append({
                "Issue": "Failed to fetch disk encryption sets",
                "Error": str(e)
            })

        # 디스크 암호화 설정 확인
        try:
            resource_groups = self.azure_api.get_all_resource_groups()

            for rg in resource_groups:
                disks = self.azure_api.list_computer_by_resource_group(rg)

                for disk in disks:
                    try:
                        # 암호화 타입과 관련된 속성 탐색
                        encryption_settings = disk.encryption_settings_collection
                        encryption_type = disk.encryption.type if hasattr(disk.encryption, 'type') else "Not Configured"
                        key_vault = (
                            disk.encryption.key_vault_properties.key_url 
                            if hasattr(disk.encryption, 'key_vault_properties') and disk.encryption.key_vault_properties 
                            else "N/A"
                        )

                        if encryption_type == "EncryptionAtRestWithCustomerKey":
                            evidence.append({
                                "Disk": disk.name,
                                "ResourceGroup": rg,
                                "EncryptionType": "Customer-Managed Key (Key Vault)",
                                "KeyVaultURL": key_vault
                            })
                        elif encryption_type == "EncryptionAtRestWithPlatformKey":
                            evidence.append({
                                "Disk": disk.name,
                                "ResourceGroup": rg,
                                "EncryptionType": "Platform-Managed Key"
                            })
                        else:
                            evidence.append({
                                "Disk": disk.name,
                                "ResourceGroup": rg,
                                "EncryptionType": "Unknown or Not Configured"
                            })
                    except Exception as e:
                        evidence.append({
                            "Issue": f"Failed to fetch encryption details for disk {disk.name}",
                            "ResourceGroup": rg,
                            "Error": str(e)
                        })

        except Exception as e:
            evidence.append({
                "Issue": "Failed to fetch disks",
                "Error": str(e)
            })

        return self.azure_api.evaluate_result(evidence, "디스크 암호화 설정이 미흡합니다.", "양호합니다.")

    # 통신구간 암호화 설정 - 자동화
    # 완성
    def D04(self):
        evidence = []

        # VPN 및 가상 네트워크 게이트웨이 설정 확인
        try:
            # 모든 리소스 그룹 가져오기
            resource_groups = self.azure_api.list_resource_client_groups()
            for rg in resource_groups:
                gateways = self.azure_api.list_network_client_virtual_network_gateways(rg.name)
                for gateway in gateways:
                    if gateway.vpn_type != "RouteBased":
                        evidence.append({
                            "Gateway": gateway.name,
                            "ResourceGroup": rg.name,
                            "VPNType": gateway.vpn_type,
                            "Location": gateway.location
                        })
        except Exception as e:
            evidence.append({"Issue": "Failed to fetch VPN configurations", "Error": str(e)})

        # 스토리지 계정에 TLS 설정 확인
        try:
            storage_accounts = self.azure_api.list_storage_accounts()
            for account in storage_accounts:
                # Resource Group 이름 추출
                resource_group_name = account.id.split("/")[4]
                properties = self.azure_api.get_storage_properties(resource_group_name, account.name)
                if not properties.enable_https_traffic_only or properties.minimum_tls_version != "TLS1_2":
                    evidence.append({
                        "StorageAccount": account.name,
                        "EnableHttpsTrafficOnly": properties.enable_https_traffic_only,
                        "MinimumTLSVersion": properties.minimum_tls_version
                    })
        
        except Exception as e:
            evidence.append({"Issue": "Failed to fetch storage account configurations", "Error": str(e)})
        
        # SQL 서버에서 TLS를 통한 암호화 설정 확인
        try:
            servers = self.azure_api.list_sql_servers()
            for server in servers:
                properties = self.azure_api.get_sql_client_servers(server.resource_group_name, server.name)
                if not properties.encryption_protector:
                    evidence.append({
                        "SQLServer": server.name,
                        "EncryptionProtector": "Not Configured",
                        "Location": server.location
                    })
        except Exception as e:
            evidence.append({"Issue": "Failed to fetch SQL server configurations", "Error": str(e)})

        # 네트워크 보안 그룹(NSG)에서 SSH 및 TLS 트래픽 허용 여부 확인
        try:
            nsgs = self.azure_api.get_network_security_groups()
            for nsg in nsgs:
                for rule in nsg.security_rules:
                    if rule.access == "Allow" and (rule.destination_port_range in ["22", "443"]):
                        evidence.append({
                            "NSG": nsg.name,
                            "Rule": rule.name,
                            "Port": rule.destination_port_range,
                            "Protocol": rule.protocol
                        })
        except Exception as e:
            evidence.append({"Issue": "Failed to fetch NSG rules", "Error": str(e)})

        return self.azure_api.evaluate_result(evidence, "통신 구간 암호화 설정이 미흡합니다.", "양호합니다.")

    # 키 자격 증명 모음 회전 정책 관리 - 자동화
    # 완성
    def D05(self):
        evidence = []

        try:
            keyvaults = self.azure_api.list_keyvaults()
            for vault in keyvaults:
                vault_name = vault.name
                resource_group = vault.id.split('/')[4]
                keys = self.azure_api.list_keys_by_resgp_vn(resource_group, vault_name)
                for key in keys:
                    policy = self.azure_api.check_key_rotation_policy(vault_name, key.name)
                    if policy.get("RotationDays") != "Not Set" and int(policy["RotationDays"]) > 90:
                        evidence.append({
                            "VaultName": vault_name,
                            "KeyName": key.name,
                            "RotationDays": policy["RotationDays"]
                        })
                    elif policy.get("RotationDays") == "Not Set":
                        evidence.append({
                            "VaultName": vault_name,
                            "KeyName": key.name,
                            "RotationDays": "Not Set"
                        })
                    
        except Exception as e:
            evidence.append({"Issue": "Failed to fetch key rotation policies", "Error": str(e)})

        return self.azure_api.evaluate_result(evidence, "사용자 고유키에 대한 회전 정책이 기준에 맞지 않습니다.", "양호합니다.")

    # 감사 로그 설정 - 자동화
    # 완성
    def D06(self):
        evidence = []
        resource_type = "microsoft.aadiam/diagnosticSettings"

        try:
            resources  = self.azure_api.list_resources()
            ad_resource = [res for res in resources if resource_type in res.type.lower()]
            if not ad_resource:
                return self.azure_api.evaluate_result(evidence, "AD 서비스가 활성화되어 있지 않습니다.", "AD 서비스가 활성화되어 있지 않습니다.")

            for resource in ad_resource:
                diagnostic_settings = self.azure_api.get_diagnostic_settings(resource.id)
                if diagnostic_settings:
                    for setting in diagnostic_settings:
                        logs = setting.logs
                        if logs:
                            required_categories = {"AuditLogs", "SignInLogs", "RiskyUsers", "UserRiskEvents"}
                            enabled_categories = {log.category for log in logs if log.enabled}
                            missing_categories = required_categories - enabled_categories
                            if missing_categories:
                                evidence.append({
                                    "ResourceId": resource.id,
                                    "MissingCategories": list(missing_categories)
                                })
                        else:
                            evidence.append({
                                "ResourceId": resource.id,
                                "Issue": "No diagnostic logs enabled"
                            })
                else:
                    evidence.append({
                        "ResourceId": resource.id,
                        "Issue": "No diagnostic settings found"
                    })
        except Exception as e:
            evidence.append({"Issue": "Failed to fetch diagnostic settings", "Error": str(e)})

        return self.azure_api.evaluate_result(evidence, "감사 로그 설정이 미흡합니다.", "양호합니다.")

    # 인스턴스 서비스 감사 로그 설정 - 일부 자동화
    # 완성 (리소스 공급자 수동 추가 필요)
    def D07(self):
        evidence = []

        # Microsoft.Insights 등록 여부 확인
        # az provider register --namespace Microsoft.Insights
        registration_issue = self.azure_api.check_insights_registration(self.azure_api.subscription_id)
        if registration_issue:
            evidence.append(registration_issue)
            return {"weak": True, "message": "Microsoft.Insights 리소스 공급자 등록이 필요합니다.", "evidence": evidence}

        try:
            # 모든 리소스 그룹 가져오기
            resource_group = self.azure_api.list_client_resource_groups()

            for rg in resource_group:
                # 리소스 그룹 객체에서 이름 가져오기
                rg_name = rg.name
                try:
                    # 리소스 그룹 내 가상 머신 가져오기
                    vms = self.azure_api.list_compute_virtual_machines(rg_name)
                    for vm in vms:
                        resource_id = vm.id
                        try:
                            diagnostic_settings = self.azure_api.get_diagnostic_settings(resource_id)
                            if diagnostic_settings:
                                for setting in diagnostic_settings:
                                    logs = setting.logs
                                    if logs:
                                        syslog_logs = [log for log in logs if log.category == "Syslog" and log.enabled]
                                        if not syslog_logs:
                                            evidence.append({
                                                "VMName": vm.name,
                                                "ResourceGroup": rg.name,
                                                "Issue": "Syslog collection not enabled"
                                            })
                                    else:
                                        evidence.append({
                                            "VMName": vm.name,
                                            "ResourceGroup": rg.name,
                                            "Issue": "No diagnostic logs enabled"
                                        })
                            else:
                                evidence.append({
                                    "VMName": vm.name,
                                    "ResourceGroup": rg.name,
                                    "Issue": "No diagnostic settings found"
                                })
                        except Exception as e:
                            evidence.append({
                                "VMName": vm.name,
                                "ResourceGroup": rg.name,
                                "Issue": "Error fetching diagnostic settings",
                                "Error": str(e)
                            })
                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to fetch VMs for resource group {rg_name}",
                        "Error": str(e)
                    }) 
        except Exception as e:
            evidence.append({"Issue": "Failed to fetch VMs", "Error": str(e)})

        return self.azure_api.evaluate_result(evidence, "인스턴스 서비스 감사 로그 설정이 미흡합니다.", "양호합니다.")

    # 네트워크 서비스 감사 로그 설정 - 완성
    # 완성
    def D08(self):
        evidence = []

        virtual_networks = self.azure_api.get_virtual_networks()
        try:
            for vnet in virtual_networks:
                resource_id = vnet.id
                diagnostic_settings = self.azure_api.get_diagnostic_settings(resource_id)

                if not diagnostic_settings:
                    evidence.append({
                        "VirtualNetwork": vnet.name,
                        "ResourceGroup": vnet.id.split("/")[4],
                        "Issue": "No diagnostic settings found",
                    })
        except Exception as e:
            evidence.append({"Issue": "Failed to fetch VMs", "Error": str(e)})

        return self.azure_api.evaluate_result(evidence, "네트워크 서비스 감사 로그 설정이 미흡합니다.", "양호합니다.")

    # 기타 서비스 감사 로그 설정 - 자동화
    # 완성
    def D09(self):
        evidence = []

        key_vaults = self.azure_api.list_keyvaults()
        
        if not key_vaults:
            return self.azure_api.evaluate_result({"Issue": "No Key Vaults found."}, "기타 서비스 감사 로그 설정이 미흡합니다.", "양호합니다.")

        for kv in key_vaults:
            resource_id = kv.id
            diagnostic_settings = self.azure_api.get_diagnostic_settings(resource_id)

            if not diagnostic_settings:
                evidence.append({
                    "KeyVault": kv.name,
                    "ResourceGroup": kv.id.split("/")[4],
                    "Issue": "No diagnostic settings found",
                })

        return self.azure_api.evaluate_result(evidence, "기타 서비스 감사 로그 설정이 미흡합니다.", "양호합니다.")

    # 리소스 그룹 잠금 - 자동화
    # 완성
    def D10(self):
        evidence = []

        # 모든 리소스 그룹 가져오기
        resource_groups = self.azure_api.list_resource_groups()
        if not resource_groups:
            return self.azure_api.evaluate_result([], "리소스 잠금 설정이 미흡합니다.", "양호합니다.")
        
        # 각 리소스 그룹에 대해 잠금 설정 확인
        for rg_name in resource_groups:
            locks = self.azure_api.get_locks_for_resource_group(rg_name)
            if not locks:
                evidence.append({
                    "ResourceGroup": rg_name,
                    "Issue": "No locks found",
                })
            else:
                for lock in locks:
                    evidence.append({
                        "ResourceGroup": rg_name,
                        "LockName": lock.name,
                        "LockLevel": lock.level,
                    })

        return self.azure_api.evaluate_result(evidence, "리소스 그룹 잠금 설정이 미흡합니다.", "양호합니다.")

    # 백업 사용 여부 - 자동화
    # 완성
    def D11(self):
        evidence = []

        # 모든 Recovery Services Vault 가져오기
        recovery_vaults = self.azure_api.list_recovery_vaults()
        if not recovery_vaults:
            return self.azure_api.evaluate_result(
                {"Issue": "백업 정책이 없습니다."},
                "백업 정책이 미흡합니다.",
                "양호합니다."
            )

        for vault in recovery_vaults:
            vault_name = vault.name
            resource_group_name = vault.id.split("/")[4]

            # Vault의 백업 정책 가져오기
            backup_policies = self.azure_api.list_backup_policies(resource_group_name, vault_name)
            if not backup_policies:
                evidence.append({
                    "VaultName": vault_name,
                    "ResourceGroup": resource_group_name,
                    "Issue": "No backup policies found",
                })

            # Vault의 보호된 아이템 가져오기
            protected_items = self.azure_api.list_protected_items(resource_group_name, vault_name)
            if not protected_items:
                evidence.append({
                    "VaultName": vault_name,
                    "ResourceGroup": resource_group_name,
                    "Issue": "No protected items found",
                })

        return self.azure_api.evaluate_result(evidence, "백업 정책 설정이 미흡합니다.", "양호합니다.")