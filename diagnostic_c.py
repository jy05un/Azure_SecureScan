from azure_api import AZUREAPI

class DiagnosticC:
    def __init__(self, credentials_file):
        self.azure_api = AZUREAPI(credentials_file)

    # 가상 네트워크 리소스 관리 - 일부 자동화
    # 완성 (재차 확인 필요)
    def C01(self):
        evidence = []

        try:
            # 모든 가상 네트워크 가져오기
            virtual_networks = self.azure_api.list_resources("Microsoft.Network/virtualNetworks")

            for vnet in virtual_networks:
                virtual_network_name = vnet.name
                # resourceGroup 추출
                resource_group_name = vnet.id.split("/")[4]

                try:
                    # 가상 네트워크에 연결된 디바이스 가져오기
                    public_ip_of_connected_devices = self.azure_api.get_public_ip_of_connected_devices(resource_group_name, virtual_network_name)
                    

                    if public_ip_of_connected_devices:
                            evidence.append(public_ip_of_connected_devices)
                        
                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to fetch connected devices for VNet {virtual_network_name}",
                        "Error": str(e)
                    })
            

        except Exception as e:
            return self.azure_api.evaluate_result(
                [{"Issue": "Failed to fetch virtual networks", "Error": str(e)}],
                "연결된 디바이스 공용 IP 관리가 미흡합니다.",
                "연결된 디바이스에 공용 IP가 없습니다."
            )

        return self.azure_api.evaluate_result(evidence, "연결된 디바이스 공용 IP 관리가 미흡합니다.", "양호합니다.")
    
    # 내부 가상 네트워크 보안 관리 - 자동화
    # 완성
    def C02(self):
        evidence = []

        try:
            # 모든 가상 네트워크 게이트웨이 확인
            resource_groups = self.azure_api.get_all_resource_groups()
            for rg in resource_groups:
                gateways = self.azure_api.get_virtual_network_gateways(rg)
                for gateway in gateways:
                    vpn_configs = self.azure_api.get_vpn_gateway_configurations(rg, gateway.name)
                    if not vpn_configs:
                        evidence.append({
                            "GatewayName": gateway.name,
                            "ResourceGroup": rg,
                            "Issue": "No VPN configurations found."
                        })
                    else:
                        for config in vpn_configs:
                            evidence.append({
                                "GatewayName": gateway.name,
                                "ResourceGroup": rg,
                                "VPNConfiguration": config
                            })
            
            # 모든 가상 머신의 베스천 연결 확인
            for rg in resource_groups:
                vms = self.azure_api.compute_client.virtual_machines.list(rg)
                for vm in vms:
                    bastion_connections = self.azure_api.check_bastion_connection(rg, vm.name)
                    if not bastion_connections:
                        evidence.append({
                            "VMName": vm.name,
                            "ResourceGroup": rg,
                            "Issue": "No Bastion connection found."
                        })
                    else:
                        for connection in bastion_connections:
                            evidence.append({
                                "VMName": vm.name,
                                "ResourceGroup": rg,
                                "BastionConnection": connection
                            })

        except Exception as e:
            return {"weak": True, "message": "Error occurred during access control check.", "evidence": str(e)}

        return self.azure_api.evaluate_result(evidence, "내부 가상 네트워크 보안 관리가 미흡합니다.", "양호합니다.")
    
    # 보안그룹 인/아웃바운드 ANY 설정 관리 - 자동화
    # 완성성
    def C03(self):
        evidence = []

        try:
            # 모든 네트워크 보안 그룹 가져오기
            nsgs = self.azure_api.get_network_security_groups()

            for nsg in nsgs:
                resource_group_name = nsg.id.split('/')[4] # 리소스 그룹 이름 추출
                nsg_name = nsg.name

                # 보안 규칙 확인
                security_rules = self.azure_api.get_security_rules(resource_group_name, nsg_name)

                for rule in security_rules:
                    port = rule.destination_port_range
                    direction = rule.direction
                    if port == "*" or port.lower() == "any":
                        evidence.append({
                            "NSGName": nsg_name,
                            "ResourceGroup": resource_group_name,
                            "RuleName": rule.name,
                            "Direction": direction,
                            "Port": port,
                            "Access": rule.access
                        })
        except Exception as e:
            return {"weak": True, "message": "Error occurred during NSG security check.", "evidence": str(e)}

        return self.azure_api.evaluate_result(evidence, "보안그룹 인/아웃바운드 ANY 설정이 존재합니다.", "양호합니다.")
    
    # 보안그룹 인/아웃바운드 불필요 정책 관리 - 자동화
    # 완성
    def C04(self):
        evidence = []

        try:
            # 모든 네트워크 보안 그룹 가져오기
            nsgs = self.azure_api.get_network_security_groups()

            for nsg in nsgs:
                resource_group_name = nsg.id.split('/')[4] # 리소스 그룹 이름 추출
                nsg_name = nsg.name

                # 보안 규칙 확인
                security_rules = self.azure_api.get_security_rules(resource_group_name, nsg_name)

                for rule in security_rules:
                    source = rule.source_address_prefix
                    destination = rule.destination_address_prefix
                    direction = rule.direction

                    # 불필요한 정책 확인: source 또는 destination이 "*" 또는 "any"인 경우
                    if source == "*" or destination == "*":
                        evidence.append({
                            "NSGName": nsg_name,
                            "ResourceGroup": resource_group_name,
                            "RuleName": rule.name,
                            "Direction": direction,
                            "Source": source,
                            "Destination": destination,
                            "Access": rule.access
                        })

        except Exception as e:
            return {"weak": True, "message": "Error occurred during NSG policy check.", "evidence": str(e)}

        return self.azure_api.evaluate_result(evidence, "보안그룹 인/아웃바운드 불필요 정책이 존재합니다.", "양호합니다.")
    
    # 방화벽 ANY 정책 설정 관리 - 자동화
    # 완성
    def C05(self):
        evidence = []

        # 방화벽 정책 확인인
        try:
            # 모든 방화벽 정책 가져오기
            firewall_policies = self.azure_api.get_firewall_policies()

            for policy in firewall_policies:
                policy_name = policy.name
                resource_group_name = policy.id.split('/')[4]  # 리소스 그룹 이름 추출

                try:
                    # 방화벽 정책의 규칙 컬렉션 가져오기
                    rule_collections = self.azure_api.get_firewall_policy_rule_collections(resource_group_name, policy_name)

                    for rule in rule_collections:
                        rules = rule.rules
                        for rule_detail in rules:
                            source = rule_detail.source_addresses
                            destination = rule_detail.destination_addresses

                            # Any 규칙 탐지
                            if "*" in source or "*" in destination:
                                evidence.append({
                                    "PolicyName": policy_name,
                                    "ResourceGroup": resource_group_name,
                                    "RuleName": rule_detail.name,
                                    "Source": source,
                                    "Destination": destination,
                                    "RuleType": rule_detail.rule_type
                                })

                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to fetch rules for policy {policy_name}",
                        "Error": str(e)
                    })

        except Exception as e:
            return {"weak": True, "message": "Error occurred during firewall policy check.", "evidence": str(e)}

        # DNAT 확인
        try:
            # 모든 방화벽 가져오기
            firewalls = self.azure_api.get_firewalls()

            for firewall in firewalls:
                firewall_name = firewall.name
                resource_group_name = firewall.id.split('/')[4] # 리소스 그룹 이름 추출
                print(resource_group_name)

                try:
                    # 방화벽의 DNAT 규칙 가져오기
                    rules = self.azure_api.get_firewall_rules(resource_group_name, firewall_name)

                    for rule in rules:
                        source = rule.source_addresses
                        destination = rule.destination_addresses

                        # Any 규칙 탐지
                        if "*" in source or "*" in destination:
                            evidence.append({
                                "FirewallName": firewall_name,
                                "ResourceGroup": resource_group_name,
                                "Source": source,
                                "Destination": destination,
                                "RuleType": "DNAT"
                            })


                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to fetch DNAT rules for firewall {firewall_name}",
                        "Error": str(e)
                    })

        except Exception as e:
            return {"weak": True, "message": "Error occurred during DNAT rule check.", "evidence": str(e)}

        return self.azure_api.evaluate_result(evidence, "방화벽 ANY 정책 설정이 존재합니다.", "양호합니다.")

    # 완성
    def C06(self):
        evidence = []

        # 방화벽 정책 확인인
        try:
            # 모든 방화벽 정책 가져오기
            firewall_policies = self.azure_api.get_firewall_policies()

            for policy in firewall_policies:
                policy_name = policy.name
                resource_group_name = policy.id.split('/')[4]  # 리소스 그룹 이름 추출

                try:
                    # 방화벽 정책의 규칙 컬렉션 가져오기
                    rule_collections = self.azure_api.get_firewall_policy_rule_collections(resource_group_name, policy_name)

                    for rule in rule_collections:
                        rules = rule.rules
                        for rule_detail in rules:
                            source = rule_detail.source_addresses
                            destination = rule_detail.destination_addresses
                            protocol = rule_detail.protocols
                            ports = rule_detail.destination_ports

                            # 불필요한 규칙 탐지 (과도한 범위 확인)
                            if "*" in source or "*" in destination or "*" in ports or "Any" in protocol:
                                evidence.append({
                                    "PolicyName": policy_name,
                                    "ResourceGroup": resource_group_name,
                                    "RuleName": rule_detail.name,
                                    "Source": source,
                                    "Destination": destination,
                                    "Ports": ports,
                                    "Protocol": protocol
                                })

                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to fetch rules for policy {policy_name}",
                        "Error": str(e)
                    })

        except Exception as e:
            return {"weak": True, "message": "Error occurred during firewall policy check.", "evidence": str(e)}

        # DNAT 확인
        try:
            # 모든 방화벽 가져오기
            firewalls = self.azure_api.get_firewalls()

            for firewall in firewalls:
                firewall_name = firewall.name
                resource_group_name = firewall.id.split('/')[4]  # 리소스 그룹 이름 추출

                try:
                    # 방화벽의 DNAT 규칙 가져오기
                    rules = self.azure_api.get_firewall_rules(resource_group_name, firewall_name)

                    for rule in rules:
                        source = rule.source_addresses
                        destination = rule.destination_addresses
                        protocol = rule.protocols
                        ports = rule.destination_ports

                        # 불필요한 규칙 탐지 (과도한 범위 확인)
                        if "*" in source or "*" in destination or "*" in ports or "Any" in protocol:
                            evidence.append({
                                "FirewallName": firewall_name,
                                "ResourceGroup": resource_group_name,
                                "Source": source,
                                "Destination": destination,
                                "Ports": ports,
                                "Protocol": protocol
                            })

                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to fetch DNAT rules for firewall {firewall_name}",
                        "Error": str(e)
                    })

        except Exception as e:
            return {"weak": True, "message": "Error occurred during DNAT rule check.", "evidence": str(e)}

        return self.azure_api.evaluate_result(evidence, "방화벽 불필요 정책이 존재합니다.", "양호합니다.")

    # NAT 게이트웨이 서브넷 연결 관리 - 일부 자동화
    # 완성 (해당 서브넷이 필요한 서브넷인지 확인 필요)
    def C07(self):
        evidence = []

        try:
            # 모든 리소스 그룹 가져오기
            resource_groups = self.azure_api.list_resource_groups()

            for resource_group_name in resource_groups:
                try:
                    # 리소스 그룹 내 NAT 게이트웨이 가져오기
                    nat_gateways = self.azure_api.network_client.nat_gateways.list(resource_group_name)

                    for nat_gateway in nat_gateways:
                        nat_gateway_name = nat_gateway.name

                        # NAT 게이트웨이에 연결된 서브넷 확인
                        connected_subnets = nat_gateway.subnets

                        if not connected_subnets:
                            evidence.append({
                                "Issue": f"No subnets connected to NAT Gateway {nat_gateway_name}",
                                "ResourceGroup": resource_group_name
                            })
                            continue

                        for subnet in connected_subnets:
                            subnet_id = subnet.id

                            # 서브넷의 상세 정보 가져오기
                            subnet_details = self.azure_api.network_client.subnets.get(
                                resource_group_name,
                                subnet_id.split('/')[-3],  # VNet 이름 추출
                                subnet_id.split('/')[-1]   # 서브넷 이름 추출
                            )

                            # 서브넷 속성 검사
                            address_prefix = subnet_details.address_prefix
                            delegations = subnet_details.delegations

                            # 취약 여부 판단 (임의 로직: 퍼블릭 네트워크 연결 여부 확인)
                            if address_prefix == '0.0.0.0/0' or not delegations:
                                evidence.append({
                                    "NATGatewayName": nat_gateway_name,
                                    "ResourceGroup": resource_group_name,
                                    "SubnetID": subnet_id,
                                    "AddressPrefix": address_prefix,
                                    "Delegations": [d.service_name for d in delegations] if delegations else "None"
                                })

                except Exception as e:
                    evidence.append({
                        "Issue": f"Failed to fetch NAT Gateway details in resource group {resource_group_name}",
                        "Error": str(e)
                    })

        except Exception as e:
            return {
                "weak": True,
                "message": "Error occurred during NAT Gateway check.",
                "evidence": str(e)
            }

        return self.azure_api.evaluate_result(evidence, "NAT 게이트웨이 서브넷 연결이 존재합니다.(수동 확인 필요)", "양호합니다.")

    # 스토리지 계정 보안 설정 - 자동화
    # 완성
    def C08(self):
        evidence = []

        try:
            # 모든 스토리지 계정 가져오기
            storage_accounts = self.azure_api.list_storage_accounts()

            for account in storage_accounts:
                account_name = account.name
                resource_group_name = account.id.split('/')[4]

                try:
                    # 스토리지 계정 구성 가져오기
                    properties = self.azure_api.get_storage_properties_network_rule_set(resource_group_name, account_name)

                    # 보안 전송 필요 여부 확인
                    secure_transfer_required = account.enable_https_traffic_only

                    # 최소 TLS 버전 확인
                    minimum_tls_version = account.minimum_tls_version

                    # 공용 네트워크 액세스 여부 확인
                    public_network_access = properties.default_action

                    # 취약 여부 판단
                    if not secure_transfer_required or minimum_tls_version != "TLS1_2" or public_network_access == "Allow":
                        evidence.append({
                                "StorageAccount": account_name,
                                "ResourceGroup": resource_group_name,
                                "SecureTransferRequired": secure_transfer_required,
                                "MinimumTLSVersion": minimum_tls_version,
                                "PublicNetworkAccess": public_network_access
                            })
                except Exception as e:
                        evidence.append({
                            "Issue": f"Failed to fetch properties for storage account {account_name}",
                            "Error": str(e)
                        })

        except Exception as e:
                return self.azure_api.evaluate_result(
                    [{"Issue": "Failed to fetch storage accounts", "Error": str(e)}],
                    "스토리지 계정 보안 설정 확인 중 오류가 발생했습니다.",
                    "스토리지 계정 보안 설정이 양호합니다."
                )

        return self.azure_api.evaluate_result(evidence, "스토리지 계정 보안 설정이 취약합니다.", "양호합니다.")

    # 스토리지 계정 공유 액세스 서명 정책 관리 - 일부 자동화
    # 완성 (SAS 속성 변경 가능)
    def C09(self):
        evidence = []

        try:
            # 모든 스토리지 계정 가져오기
            storage_accounts = self.azure_api.list_storage_accounts()

            for account in storage_accounts:
                account_name = account.name
                resource_group_name = account.id.split('/')[4]

                try:
                    # SAS 토큰 검사
                    blob_service_client = self.azure_api.get_blob_token(account_name)

                    containers = blob_service_client.list_containers()
                    for container in containers:
                        container_name = container.name
                        container_client = blob_service_client.get_container_client(container_name)

                        # SAS 토큰 속성 확인
                        sas_properties = container_client.get_account_information()

                        # permissions 및 ip_range 확인 (수정 가능)
                        permissions = sas_properties.get("permissions", "")
                        start_time = sas_properties.get("start", None)
                        expiry_time = sas_properties.get("expiry", None)
                        ip_range = sas_properties.get("ip_range", None)
                        protocol = sas_properties.get("protocol", None)

                        # 설정 검사
                        if (
                            "w" in permissions or "d" in permissions or
                            not start_time or not expiry_time or
                            not ip_range or protocol != "https"
                        ):
                            evidence.append({
                                "StorageAccount": account_name,
                                "ResourceGroup": resource_group_name,
                                "Container": container_name,
                                "Permissions": permissions,
                                "StartTime": start_time,
                                "ExpiryTime": expiry_time,
                                "IPRange": ip_range,
                                "Protocol": protocol
                            })

                except Exception as e:
                        evidence.append({
                            "Issue": f"Failed to fetch SAS properties for storage account {account_name}",
                            "Error": str(e)
                        })

        except Exception as e:
                return self.azure_api.evaluate_result(
                    [{"Issue": "Failed to fetch storage accounts", "Error": str(e)}],
                    "SAS 설정 확인 중 오류가 발생했습니다.",
                    "SAS 설정이 양호합니다."
                )

        return self.azure_api.evaluate_result(evidence, "SAS 설정이 취약합니다.", "양호합니다.")