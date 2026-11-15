# Compliance engine

Building codes as rule packs that answer questions with citations to the official text and to the law that adopted it.

- [`spec/norm-ir-v0.md`](spec/norm-ir-v0.md): the rule format.
- [`packs/ibc-2024`](packs/ibc-2024): 2024 IBC egress starter set (draft, not yet reviewed by a code professional).
- [`packs/austin-2024`](packs/austin-2024): City of Austin Ordinance No. 20250410-045 on top of it.
- [`packs/jp-bsa-egress`](packs/jp-bsa-egress): 建築基準法施行令 stairs and egress (令23–25, 117–125), from e-Gov.
- [`packs/uk-adb-v2`](packs/uk-adb-v2): Approved Document B Volume 2 means of escape (England), under the Open Government Licence.
- [`packs/ada-2010`](packs/ada-2010): 2010 ADA Standards, model-checkable provisions.
- [`engine/normir`](engine/normir): reference evaluator and validator.
- [`bench`](bench): the consistency benchmark (models answering directly vs the kernel) and the NIBS clinic check across all four packs.

```sh
uv run normir validate packs/austin-2024
uv run normir ask packs/austin-2024 required_corridor_width --profile examples/riverside-medical-office.yaml
uv run normir ask packs/austin-2024 max_exit_access_travel_distance --profile examples/riverside-medical-office.yaml --set sprinkler_system=none
uv run normir status packs/austin-2024 903.3.1.1
uv run pytest
uv run python bench/kernel.py bench/japan.yaml
uv run python bench/score.py bench/japan.yaml bench/results/*/japan.json
uv run --with ifcopenshell python -m bench.clinic.check <path to Clinic_A_20110906.ifc>
```

## Web app

```sh
uv run uvicorn app.main:app --port 8765          # / : code repositories, /buildings : drawings and models
uv run python -m app.seed                        # example building projects from app/seeds.yaml (real, openly licensed sets)
```

Building projects take IFC models (`adapters/ifc.py`), DXF drawings (`adapters/dxf.py`) and PDF or image sheets
(`adapters/drawings/`: text layer, or OCR where text is drawn as outlines or scanned), or a .zip of them. Every
verdict cites the code section and shows the sheet region or model element it rests on; classifications the
drawings can't show (occupancy group, which stairs are exits) are asked once per building or element type.
