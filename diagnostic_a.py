from azure_api import AZUREAPI
from datetime import datetime, timedelta

class DiagnosticA:
    def __init__(self, credentials_file):
        self.azure_api = AZUREAPI(credentials_file)

    # AD 사용자 계정 관리 - 자동화
    # 완성
    def A01(self):
        evidence = []

        # 전역 관리자 권한이 있는 역할 이름 (Azure에서는 기본적으로 "User Access Administrator" 또는 "Global Administrator")
        GLOBAL_ADMIN_ROLE_NAMES = ["Global Administrator", "Owner"]

        # 역할 정의(특히 전역 관리자에 해당하는 역할 확인)
        role_definitions = self.azure_api.auth_client.role_definitions.list(
            scope=f"/subscriptions/{self.azure_api.subscription_id}"
        )

        global_admin_role_ids = [
            role.id for role in role_definitions if role.role_name in GLOBAL_ADMIN_ROLE_NAMES
        ]

        # 역할 할당된 사용자/서비스 주체 확인
        role_assignments = self.azure_api.auth_client.role_assignments.list_for_scope(
            scope=f"/subscriptions/{self.azure_api.subscription_id}"
        )
        for assignment in role_assignments:
            if assignment.role_definition_id in global_admin_role_ids:
                evidence.append({"PrincipalId": assignment.principal_id, "RoleDefinitionId": assignment.role_definition_id, "Scope": assignment.scope})

        return self.azure_api.evaluate_result(evidence, "AD 사용자 계정 관리가 미흡합니다.", "양호합니다.")
    
    # AD 사용자 프로필 및 디렉터리 식별 관리 - 자동화화
    # 완성
    def A02(self):
        evidence = []

        # 모든 사용자 정보 가져오기
        users = self.azure_api.get_all_users()

        # 필수 항목 검사
        for user in users:
            missing_fields = []
            if not user.get("id"):
                missing_fields.append("ID")
            if not user.get("displayName"):
                missing_fields.append("Display Name")
            if not user.get("jobTitle"):
                missing_fields.append("Job Title")
            if not user.get("main"):
                missing_fields.append("Main")
            if not user.get("mobilePhone"):
                missing_fields.append("Mobile Phone")

        # 필수 항목이 누락된 경우 기록
        if missing_fields:
            evidence.append({"UserId": user.get("Id"), "Display Name": user.get("displayName", "N/A"), "Missing Fields": missing_fields})

        return self.azure_api.evaluate_result(evidence, "프로필 필수 항목(ID, 작업정보, 연락처 등)이 미흡합니다.", "양호합니다.")
    
    # AD 그룹 소유자 및 구성원 관리 - 자동화
    # 완성
    def A03(self):
        evidence = []

        # 모든 그룹 가져오기
        groups = self.azure_api.get_all_groups()

        for group in groups:
            group_id = group.get("id")
            group_name = group.get("displayName", "Unknown")

            # 소유자와 구성원 정보 가져오기
            owners = self.azure_api.get_group_owners(group_id)
            members = self.azure_api.get_group_members(group_id)

            # 누락된 정보 확인
            missing = {}
            if not owners:
                missing["Owners"] = "No owners assigned"
            if not members:
                missing["Members"] = "No members assigned"

            if missing:
                evidence.append({"GroupName": group_name, "GroupId": group_id, "Missing": missing})

        return self.azure_api.evaluate_result(evidence, "AD 그룹 소유자 및 구성원 관리가 미흡합니다.", "양호합니다.")
    
    # AD 게스트 사용자 - 자동화
    # 완성
    def A04(self):
        evidence = []

        users = self.azure_api.get_all_users()

        # 현재 시간
        current_time = datetime.utcnow()
        expiration_threshold = current_time - timedelta(days=90) # 90일 기준

        for user in users:
            user_pricipal_name = user.get("userPrincipalName", "Unknown")
            user_type = user.get("userType", "Unknown")
            account_enabled = user.get("accountEnabled", True)
            last_sign_in_date = user.get("signInActivity", {}).get("lastSignInDateTime", None)

            # 게스트 사용자만 필터링
            if user_type == "Guest":
                missing_fields = []

                # 계정이 비활성화인 경우
                if not account_enabled:
                    missing_fields.append("Disabled Account")

                # 마지막 로그인 확인
                if last_sign_in_date:
                    last_sign_in_datetime = datetime.strptime(last_sign_in_date, "%Y-%m-%dT%H:%M:%SZ")
                    if last_sign_in_datetime < expiration_threshold:
                        missing_fields.append("Inactive Account")
                else:
                    missing_fields.append("No Sign-In Activity")

                # 필터링 결과 기록
                if missing_fields:
                    evidence.append({"UserPrincipalName": user_pricipal_name, "LastSignInDate": last_sign_in_date or "N/A", "Issues": missing_fields})


        return self.azure_api.evaluate_result(evidence, "AD 게스트 사용자가 존재합니다.", "양호합니다.")
    
    # AD 암호 재설정 규칙 관리 - 자동화
    # 자동화 (플랜 이슈 존재 가능)
    def A05(self):
        evidence = []

        # 1. 셀프 서비스 암호 재설정 속성 확인
        try:
            properties = self.azure_api.get_password_reset_properties()
            if not properties.get("isEnabled"):
                evidence.append({"Issue": "Self-service password reset is not enabled"})
        except Exception as e:
            evidence.append({"Issue": "Failed to fetch password reset properties", "Error": "플랜 이슈 가능성 존재, " + str(e)})

        # 2. 암호 재설정 알림 설정 확인
        try:
            notifications = self.azure_api.get_notifications_settings()
            if not notifications.get("notifyOnSelfServicePasswordReset"):
                evidence.append({"Issue": "User notifications for password reset are not enabled"})
            if not notifications.get("notifyOnAdminPasswordReset"):
                evidence.append({"Issue": "Admin notifications for password reset are not enabled"})
        except Exception as e:
            evidence.append({"Issue": "Failed to fetch password reset notifications", "Error": "플랜 이슈 가능성 존재, " + str(e)})

        # 3. 암호 재설정 인증 방법 확인
        try:
            auth_methods = self.azure_api.get_authentication_methods()
            if not auth_methods:
                evidence.append({"Issue": "No authentication methods configured for password reset"})
            else:
                for method in auth_methods.get("value", []):
                    if not method.get("isEnabled"):
                        evidence.append({"Issue": f"Authentication method {method['id']} is not enabled"})
        except Exception as e:
            evidence.append({"Issue": "Failed to fetch authentication methods", "Error": "플랜 이슈 가능성 존재, " + str(e)})

        return self.azure_api.evaluate_result(evidence, "AD 암호 재설정 규칙 관리가 미흡합니다.", "양호합니다.")

    # SSH Key 접근 관리 - 자동화
    # 완성
    def A06(self):
        evidence = []

        allowed_roles = ["Owner", "Contributor", "User Access Administrator"]

        # 리소스 그룹 및 SSH 키 이름 가져오기
        resource_groups = self.azure_api.list_resource_groups()

        for rg in resource_groups:
            ssh_keys = self.azure_api.list_ssh_keys(rg)

            # 평가를 원하는 SSH키에 대해 실행
            for ssh_key in ssh_keys:
                ssh_key_resource_id = f"/subscriptions/{self.azure_api.subscription_id}/resourceGroups/{rg}/providers/Microsoft.Compute/sshPublicKeys/{ssh_key}"
                role_assignments = self.azure_api.get_role_assignments_ssh_key(ssh_key_resource_id)
                for assignment in role_assignments:
                    role_name = self.azure_api.get_role_definition(assignment["RoleDefinitionId"])
                    if role_name not in allowed_roles:
                        evidence.append({"PrincipalId": assignment["PrincipalId"], "AssignedRole": role_name, "Scope": assignment["Scope"]})

        return self.azure_api.evaluate_result(evidence, "SSH Key 접근 관리가 미흡합니다.", "양호합니다.")

    # MFA 설정 - 자동화
    # 완성
    def A07(self):
        evidence = []

        users = self.azure_api.get_all_users()
        for user in users:
            user_id = user.get("id")
            display_name = user.get("displayName", "N/A")
            try:
                mfa_enabled = self.azure_api.get_mfa_status(user_id)
                if not mfa_enabled:
                    evidence.append({"UserId": user_id, "DisplayName": display_name, "MFAStatus": "Disabled"})
            except Exception as e:
                evidence.append({"UserId": user_id, "DisplayName": display_name, "Error": str({e}) })

        return self.azure_api.evaluate_result(evidence, "MFA 설정이 미흡합니다.", "양호합니다.")

    # MFA 계정 잠금 정책 관리 - 자동화
    # 완성
    def A08(self):
        evidence = []

        # Microsoft Authenticator 정책 확인
        authenticator_policy = self.azure_api.get_authenticator_policy()

        if not authenticator_policy.get("isEnabled"):
            evidence.append({"Issue": "Microsoft Authenticator is not enabled", "Details": authenticator_policy.get("details")})

        # Password Protection 정책 확인
        password_policy = self.azure_api.get_password_protection_policy()

        if password_policy.get("isConfigured") is False or password_policy.get("lockoutThreshold") != 5 or password_policy.get("lockoutDurationInSeconds") != 3600:
            evidence.append({"Issue": "Password protection policy does not meet the required standards", "Details": password_policy})

        return self.azure_api.evaluate_result(evidence, "MFA 계정 장금 정책 관리가 미흡합니다.", "양호합니다.")

    # 패스워드 정책 관리 - 자동화
    # 완성
    def A09(self):
        evidence = []
        not_auth_methods = []

        # 암호 재설정 속성 확인
        reset_properties = self.azure_api.get_password_reset_properties()
        if not reset_properties:
            evidence.append({"Issue": "Self-service password reset is not enabled.", "Details": "Disabled"})

        # 알림 설정 확인
        try:
            notifications = self.azure_api.get_notifications_settings()
            if notifications is None:
                evidence.append({"Issue": "Password reset notification policy is not configured.", "Details": "Policy not found."})
            else:
                if not notifications.get("notifyUsersOnPasswordReset", False):
                    evidence.append({"Issue": "User notification on password reset is not enabled."})
                if not notifications.get("notifyAdminsOnReset", False):
                    evidence.append({"Issue": "Admin notification on password reset is not enabled."})
        except:
            evidence.append({"Issue": f"Failed to fetch password reset notifications, seems to be done manually."})

        # 인증 방법 확인
        auth_methods = self.azure_api.get_authentication_methods()
        for method_id, method_details in auth_methods.items():
            if not method_details["isEnabled"]:
                not_auth_methods.append(method_id)
        if not_auth_methods:
            evidence.append({"Issue": f"Authentication methods are not enabled.", "Details": not_auth_methods})
        
        return self.azure_api.evaluate_result(evidence, "패스워드 정책 관리가 미흡합니다.", "양호합니다.")