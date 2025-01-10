# 엑셀 편집 라이브러리
# pip install openpyxl
from openpyxl import load_workbook


class Report:
    def __init__(self) -> None:
        self.load_wb = load_workbook("./report_sample.xlsx")
        self.load_wb.active
        self.load_ws = self.load_wb['Azure']

    def overwrite(self, results):
        start_row = 0
        for result in results:
            category = list(result.keys())[0]
            if category[0:1] == "a":
                start_row = 4
            if category[0:1] == "b":
                start_row = 13
            if category[0:1] == "c":
                start_row = 19
            if category[0:1] == "d":
                start_row = 28
            row = start_row+int(category[1:])
            api_cell = f"I{row}"
            result_cell = f"J{row}"
            detail_cell = f"K{row}"
            for result in result.values():
                self.load_ws[result_cell] = "N" if result["weak"] else "Y"
                self.load_ws[detail_cell] = result["message"] + \
                    "\n" + str(result["evidence"])
                self.load_ws[api_cell] = "✅"

    def save(self, filename):
        self.load_wb.save(f"./{filename}.xlsx")
