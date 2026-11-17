"""Triangle meshes of an IFC model's elements, for the chat's model preview.

    python -m app.model_mesh <model.ifc> <out.json>

Run in its own process (app.chats.model_mesh) because a geometry kernel can crash on a damaged model. Writes
{elements: [{g: GlobalId, t: IFC type, n: name, a: GlobalIds of the elements it is part of, v: base64 float32 xyz,
i: base64 uint32 triangle indices}], bbox,
triangles, skipped}: world coordinates in metres, z up. Openings are left out; spaces are kept so a cited room can be
shown. `a` lets a cited aggregate with no geometry of its own (a stair, a roof) be shown by its parts. Past MAX_TRIANGLES the rest of the elements are counted in `skipped`.
"""

from __future__ import annotations

import base64
import json
import sys
from array import array
from pathlib import Path

MAX_TRIANGLES = 1_500_000
LEAVE_OUT = {"IfcOpeningElement", "IfcVirtualElement", "IfcAnnotation", "IfcGrid"}


def mesh(ifc_path: Path) -> dict:
    import multiprocessing

    import ifcopenshell
    import ifcopenshell.geom
    import ifcopenshell.util.element

    model = ifcopenshell.open(str(ifc_path))
    settings = ifcopenshell.geom.settings()
    settings.set("use-world-coords", True)
    it = ifcopenshell.geom.iterator(settings, model, max(1, min(4, multiprocessing.cpu_count())))
    out, tris, skipped = [], 0, 0
    lo, hi = [float("inf")] * 3, [float("-inf")] * 3

    def wholes(el) -> list[str]:
        out, seen = [], set()
        while (el := ifcopenshell.util.element.get_aggregate(el)) is not None and el.id() not in seen:
            seen.add(el.id())
            out.append(el.GlobalId)
        return out
    if it.initialize():
        while True:
            shape = it.get()
            el = model.by_id(shape.id)
            if el.is_a() not in LEAVE_OUT:
                verts, faces = shape.geometry.verts, shape.geometry.faces
                if tris + len(faces) // 3 > MAX_TRIANGLES:
                    skipped += 1
                elif faces:
                    for k in range(0, len(verts), 3):
                        for a in range(3):
                            lo[a], hi[a] = min(lo[a], verts[k + a]), max(hi[a], verts[k + a])
                    tris += len(faces) // 3
                    out.append({"g": el.GlobalId, "t": el.is_a(), "n": getattr(el, "Name", None) or "", "a": wholes(el),
                                "v": base64.b64encode(array("f", verts).tobytes()).decode(),
                                "i": base64.b64encode(array("I", faces).tobytes()).decode()})
            if not it.next():
                break
    return {"elements": out, "bbox": [lo, hi] if out else None, "triangles": tris, "skipped": skipped}


if __name__ == "__main__":
    Path(sys.argv[2]).write_text(json.dumps(mesh(Path(sys.argv[1]))))
