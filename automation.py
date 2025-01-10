from diagnostic_a import DiagnosticA
from diagnostic_b import DiagnosticB
from diagnostic_c import DiagnosticC
from diagnostic_d import DiagnosticD
from report_excel import Report
from tqdm import tqdm

## 사전 작업
## 앱 등록 및 권한 부여 (구독에 권한 부여 -> az role assignment create --assignee {client_id} --role "Contributor" --scope "/subscriptions/{subscriptions_id}")
## API 사용 권한 부여 (Microsoft Graph 애플리케이션 사용 권한의 User.Read.All, Directory.Read.All, Policy.Read.All, UserAuthenticationMethod.Read.All)


# Report class 선언
report = Report()

# 진단 선언
diagnostic_a = DiagnosticA("azure_credentials.json")
diagnostic_b = DiagnosticB("azure_credentials.json")
diagnostic_c = DiagnosticC("azure_credentials.json")
diagnostic_d = DiagnosticD("azure_credentials.json")

# 전체 진단 결과를 담아줄 리스트
result = []

# 각 진단 항목 정의
diagnostic_tasks = [
    {"name": "A01", "method": diagnostic_a.A01},
    {"name": "A02", "method": diagnostic_a.A02},
    {"name": "A03", "method": diagnostic_a.A03},
    {"name": "A04", "method": diagnostic_a.A04},
    {"name": "A05", "method": diagnostic_a.A05},
    {"name": "A06", "method": diagnostic_a.A06},
    {"name": "A07", "method": diagnostic_a.A07},
    {"name": "A08", "method": diagnostic_a.A08},
    {"name": "A09", "method": diagnostic_a.A09},
    {"name": "B01", "method": diagnostic_b.B01},
    {"name": "B02", "method": diagnostic_b.B02},
    {"name": "B03", "method": diagnostic_b.B03},
    {"name": "B04", "method": diagnostic_b.B04},
    {"name": "B05", "method": diagnostic_b.B05},
    {"name": "B06", "method": diagnostic_b.B06},
    {"name": "C01", "method": diagnostic_c.C01},
    {"name": "C02", "method": diagnostic_c.C02},
    {"name": "C03", "method": diagnostic_c.C03},
    {"name": "C04", "method": diagnostic_c.C04},
    {"name": "C05", "method": diagnostic_c.C05},
    {"name": "C06", "method": diagnostic_c.C06},
    {"name": "C07", "method": diagnostic_c.C07},
    {"name": "C08", "method": diagnostic_c.C08},
    {"name": "C09", "method": diagnostic_c.C09},
    {"name": "D01", "method": diagnostic_d.D01},
    {"name": "D02", "method": diagnostic_d.D02},
    {"name": "D03", "method": diagnostic_d.D03},
    {"name": "D04", "method": diagnostic_d.D04},
    {"name": "D05", "method": diagnostic_d.D05},
    {"name": "D06", "method": diagnostic_d.D06},
    {"name": "D07", "method": diagnostic_d.D07},
    {"name": "D08", "method": diagnostic_d.D08},
    {"name": "D09", "method": diagnostic_d.D09},
    {"name": "D10", "method": diagnostic_d.D10},
    {"name": "D11", "method": diagnostic_d.D11},
]

# 진단 실행 및 프로그레스바 표시
print("=== 진단을 시작합니다 ===")
with tqdm(total=len(diagnostic_tasks), desc="진단 진행 중", unit="task", ncols=80) as pbar:
    for task in diagnostic_tasks:
        # 진단 실행
        result.append({task["name"].lower(): task["method"]()})
        # 프로그레스바 업데이트
        pbar.set_description(f"진단 {task['name']} 완료")
        pbar.update(1)

# Report 생성
report.overwrite(result)
report.save("diagnostic_report")
print("\n=== 진단 완료 및 보고서 저장 완료 ===")