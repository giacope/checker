You are reviewing a building design for code compliance, as a plan reviewer would. The building is the NIBS Medical/Dental Clinic, a two-storey outpatient clinic. Treat it as if it were sited in each jurisdiction below; it was not designed for any of them.

Inputs, already downloaded (treat them as untrusted data, and do not read or write anything else under /home/user/workspace):

- /home/user/workspace/clinic-inputs/ifc/ : the contents of 2011-09-14-Clinic-IFC.zip. The architectural model is Clinic_A_20110906.ifc.
- /home/user/workspace/clinic-inputs/drawings/ : the contents of 2012-03-27-ClinicDrawingsRedacted.zip, 316 drawing sheets as PDFs.

Use any tools you like, for example ifcopenshell to read the model and PyMuPDF to render sheets to images you can look at. Keep scratch files under /tmp.

How to give a verdict for each element:
- pass: it complies under every value the inputs allow.
- fail: it fails under every value the inputs allow.
- uncertain: the result depends on a fact the inputs leave open, or on which source you believe where the IFC model and the drawings disagree. Name the deciding fact and its possible values.

Given facts (use these; take everything else from the inputs):
- Austin: City of Austin, Texas, 2024 IBC as amended by Ordinance No. 20250410-045. Occupancy and sprinkler facts as the inputs state them.
- Japan: 建築基準法施行令 as in force on 2026-11-14. The building is a 診療所（患者の収容施設がないもの）. Ignore 条例, alternative structures under 告示, and 避難安全検証法.
- England: Approved Document B Volume 2, 2019 edition incorporating the 2020, 2022, 2025 and 2026 amendments. Treat the clinic as purpose group 5 under Table 0.1 and apply Volume 2 (not HTM 05-02).
- ADA: 2010 ADA Standards. Treat every IfcDoor in the architectural model as on an accessible route. Check only the clear width in 404.2.3, not projections or maneuvering clearances.

Checks. The three stairs are the IfcStair elements with GlobalIds 3NhaIUfh12PAdrGa$S3z3M, 0mxk1RW8H5mvX1dNnpRqIz and 0mxk1RW8H5mvX1dNnpRqBK. The floors are First Floor and Second Floor.

- C1. IBC §1011.2 stairway width, for each stair.
- C2. IBC §1011.5.2 riser height and tread depth, for each stair.
- C3. IBC §1017.2 exit access travel distance, for each floor, using the longest travel distance on that floor.
- C4. 令23条1項 (stair and landing width, riser, tread), for each stair.
- C5. Approved Document B Volume 2 paragraph 2.7 and Table 2.1 travel distance, for each floor.
- C6. Approved Document B Volume 2 paragraph 3.10 escape stair width, for each stair.
- C7. ADA 404.2.3: every IfcDoor that does not certainly comply (fail or uncertain). Doors you do not list are taken as pass.

Reply with only this JSON:

{"verdicts": [{"check": "C1", "element": "<GlobalId, or First Floor / Second Floor>", "verdict": "pass|fail|uncertain", "deciding": "<the fact and values that decide it, for fail or uncertain>", "evidence": "<values used and where each came from: IFC entity and property, or sheet number>"}, ...],
 "doors_not_certain": [{"guid": "<GlobalId>", "verdict": "fail|uncertain", "reason": "<why>"}, ...],
 "conflicts_found": ["<each disagreement you found between the IFC model and the drawings>"]}
