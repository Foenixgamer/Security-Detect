"""
SQS - Interfaz gráfica para las capas del spec (Capa 1-4), tkinter (stdlib).

GUI real (sin simulaciones): selecciona un paquete, ejecuta el análisis
completo Capa 1 -> Capa 4 en un hilo y muestra componentes, vulnerabilidades
y recomendaciones en pestañas. Permite exportar el informe a JSON/HTML/CSV.

La lógica vive en funciones puras (`analyze_package`, `component_rows`,
`vulnerability_rows`, `recommendations`, `format_size`) para poder testearla
sin abrir ventanas. La clase `PackageAnalyzerGUI` es solo la presentación.

Uso:
    python gui_interface.py

No reemplaza sqs_gui.py (visión del pipeline de 7 capas); es la GUI del spec
de capas 1-4.
"""

import os
import queue
import sys
import threading

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from layer1_extractor import extract_components
from layer2_analyzer import analyze_package_dynamically
from layer3_vuln_analyzer import analyze_vulnerabilities
from layer4_report_generator import (
    build_report,
    export_to_csv,
    export_to_html,
)

STAGES = [
    "Inventario de componentes (Capa 1)",
    "Análisis dinámico (Capa 2)",
    "Análisis de vulnerabilidades (Capa 3)",
    "Generación de informe (Capa 4)",
]


def format_size(num):
    """Formatea un tamaño en bytes de forma legible."""
    try:
        num = float(num)
    except (TypeError, ValueError):
        return "0 B"
    if num == 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0 or unit == "TB":
            return "{:.1f} {}".format(num, unit)
        num /= 1024.0
    return "0 B"


def analyze_package(package_path, timeout=15, run_scripts=True,
                    progress_cb=None, should_stop=None):
    """Ejecuta Capa 1 -> Capa 4 reales y devuelve el informe final.

    Args:
        package_path (str): paquete/directorio a analizar.
        timeout (int): límite por componente en Capa 2.
        run_scripts (bool): ejecutar también scripts en Capa 2.
        progress_cb (callable): recibe (indice, etiqueta) por etapa.
        should_stop (callable): si devuelve True, aborta y retorna None.

    Returns:
        dict|None: informe final del reporte de Capa 4.
    """
    def emitted(index, label):
        if progress_cb:
            progress_cb(index, label)

    def stopped():
        return bool(should_stop and should_stop())

    emitted(0, STAGES[0])
    components = extract_components(package_path)
    if stopped():
        return None

    emitted(1, STAGES[1])
    dynamic = analyze_package_dynamically(package_path, components,
                                          timeout=timeout,
                                          run_scripts=run_scripts)
    if stopped():
        return None

    emitted(2, STAGES[2])
    vulnerabilities = analyze_vulnerabilities(components, dynamic,
                                              base_dir=package_path)
    if stopped():
        return None

    emitted(3, STAGES[3])
    report = build_report(components, dynamic, vulnerabilities)
    report["package_path"] = package_path
    return report


def component_rows(report):
    """Filas para la pestaña de componentes: (path, tipo, tamaño, riesgo, exit)."""
    rows = []
    for entry in report.get("components") or []:
        comp = entry.get("component") or {}
        vuln = entry.get("vulnerabilities") or {}
        dyn = entry.get("dynamic_analysis") or {}
        risk = vuln.get("risk_level") if vuln else ""
        rows.append((str(comp.get("path", "")),
                     str(comp.get("type", "")),
                     format_size(comp.get("size")),
                     str(risk),
                     str(dyn.get("exit_code", "")) if dyn else ""))
    return rows


def vulnerability_rows(report):
    """Filas de vulnerabilidades: (componente, riesgo, problemas)."""
    rows = []
    for vuln in report.get("vulnerabilities") or []:
        rows.append((str(vuln.get("component", "")),
                     str(vuln.get("risk_level", "")),
                     ", ".join(vuln.get("issues") or [])))
    return rows


def recommendations(report):
    """Genera recomendaciones concretas a partir del informe real."""
    lines = []
    summary = report.get("summary", {})
    total = summary.get("total_components", 0)
    lines.append("Se analizaron {0} componente(s) del paquete: {1}".format(
        total, report.get("package_path", "")))

    high = summary.get("risk_distribution", {}).get("alto", 0)
    medium = summary.get("risk_distribution", {}).get("medio", 0)
    lines.append("Riesgo detectado: alto en {0}, medio en {1}.".format(
        high, medium))

    unsigned = []
    dangerous = []
    execution_fail = 0
    for entry in report.get("components") or []:
        vuln = entry.get("vulnerabilities") or {}
        details = vuln.get("details") or {}
        path = entry.get("component", {}).get("path", "")
        if details.get("signature_status") == "unsigned":
            unsigned.append(path)
        if details.get("dangerous_functions"):
            dangerous.append(path)
        if details.get("execution_status") in ("execution_error", "timeout"):
            execution_fail += 1

    if unsigned:
        lines.append("- Firmar digitalmente: " + ", ".join(sorted(unsigned))
                     + ".")
    if dangerous:
        lines.append("- Revisar funciones peligrosas en: "
                     + ", ".join(sorted(dangerous)) + ".")
    if execution_fail:
        lines.append("- {0} componente(s) no pudieron ejecutarse; revisar el"
                     " registro de Capa 2.".format(execution_fail))
    if high == 0 and medium == 0:
        lines.append("- No se detectaron vulnerabilidades relevantes.")

    if total == 0:
        lines.append("- El paquete no contiene componentes analizables.")
    return lines


def _save_all(root, report):
    from tkinter import filedialog, messagebox

    directory = filedialog.askdirectory(title="Carpeta para guardar el informe")
    if not directory:
        return
    try:
        import json
        import os
        from layer4_report_generator import generate_final_report

        json_path = os.path.join(directory, "final_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            f.write("\n")
        html_path = export_to_html(
            report, os.path.join(directory, "final_report.html"))
        csv_path = export_to_csv(
            report, os.path.join(directory, "final_report.csv"))
        messagebox.showinfo(
            "Informe", "Guardado en:\n{0}\n{1}\n{2}".format(
                json_path, html_path, csv_path))
    except Exception as exc:
        messagebox.showerror("Error", "No se pudo guardar el informe: "
                             + str(exc))


class PackageAnalyzerGUI:
    """GUI tkinter conectada a las capas reales (Capa 1-4)."""

    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk

        self.root = root
        self.q = queue.Queue()
        self.worker = None
        self.stop_event = threading.Event()
        self.report = None

        root.title("Analizador de Paquetes Seguro (Capas 1-4)")
        root.geometry("900x620")

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        top = tk.Frame(root, padx=8, pady=8)
        top.pack(fill="x")

        tk.Label(top, text="Paquete:").pack(side="left")
        self.path_var = tk.StringVar(value="")
        entry = tk.Entry(top, textvariable=self.path_var, width=55)
        entry.pack(side="left", padx=6)
        self.browse_btn = ttk.Button(top, text="Seleccionar...",
                                     command=self._browse)
        self.browse_btn.pack(side="left", padx=(0, 6))

        self.start_btn = ttk.Button(top, text="Iniciar análisis",
                                    command=self._start)
        self.start_btn.pack(side="left", padx=(0, 6))
        self.stop_btn = ttk.Button(top, text="Detener",
                                   command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 6))
        self.save_btn = ttk.Button(top, text="Guardar informe...",
                                   command=self._save, state="disabled")
        self.save_btn.pack(side="left", padx=(0, 6))

        self.progress = ttk.Progressbar(root, maximum=len(STAGES) + 1)
        self.progress.pack(fill="x", padx=8, pady=(0, 6))

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self._build_tabs()

        self.status_var = tk.StringVar(value="Listo. Selecciona un paquete.")
        tk.Label(root, textvariable=self.status_var, anchor="w",
                 fg="#1565c0").pack(fill="x", padx=8, pady=(0, 4))

        self.root.after(100, self._poll)

    # --- construcción de pestañas ---

    def _build_tabs(self):
        self._build_components_tab()
        self._build_vulnerabilities_tab()
        self._build_recommendations_tab()

    @staticmethod
    def _new_tab(notebook, title):
        import tkinter as tk
        from tkinter import ttk
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=title)
        return frame

    def _build_components_tab(self):
        import tkinter as tk
        from tkinter import ttk
        frame = self._new_tab(self.notebook, "Componentes")
        columns = ("path", "type", "size", "risk", "exit")
        labels = ("Componente", "Tipo", "Tamanio", "Riesgo", "Exit")
        self.components_tree = ttk.Treeview(frame, columns=columns,
                                            show="headings")
        for col, label in zip(columns, labels):
            self.components_tree.heading(col, text=label)
            self.components_tree.column(col, width=150)
        self._attach_scroll(frame, self.components_tree)

    def _build_vulnerabilities_tab(self):
        import tkinter as tk
        from tkinter import ttk
        frame = self._new_tab(self.notebook, "Vulnerabilidades")
        columns = ("component", "risk", "issues")
        labels = ("Componente", "Riesgo", "Problemas")
        self.vulnerabilities_tree = ttk.Treeview(frame, columns=columns,
                                                 show="headings")
        for col, label in zip(columns, labels):
            self.vulnerabilities_tree.heading(col, text=label)
            self.vulnerabilities_tree.column(col, width=220)
        self._attach_scroll(frame, self.vulnerabilities_tree)

    def _build_recommendations_tab(self):
        import tkinter as tk
        from tkinter import ttk
        frame = self._new_tab(self.notebook, "Recomendaciones")
        self.recommendations_text = tk.Text(frame, wrap="word",
                                            font=("Consolas", 10))
        self._attach_scroll(frame, self.recommendations_text,
                            widget_is_text=True)

    @staticmethod
    def _attach_scroll(parent, widget, widget_is_text=False):
        import tkinter as tk
        from tkinter import ttk
        scroll = ttk.Scrollbar(parent, orient="vertical",
                               command=getattr(widget, "yview"))
        getattr(widget, "configure")(yscrollcommand=scroll.set)
        widget.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

    # --- acciones ---

    def _browse(self):
        from tkinter import filedialog
        path = filedialog.askdirectory(title="Seleccionar paquete")
        if path:
            self.path_var.set(path)

    def _start(self):
        path = self.path_var.get().strip()
        if not path or not os.path.isdir(path):
            self.status_var.set("Selecciona un paquete (carpeta) válido.")
            return

        self.stop_event.clear()
        self.report = None
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.save_btn.configure(state="disabled")
        self.progress["value"] = 0
        self.status_var.set("Iniciando análisis...")

        self.worker = threading.Thread(target=self._run_worker, args=(path,),
                                       daemon=True)
        self.worker.start()

    def _stop(self):
        self.stop_event.set()
        self.status_var.set("Deteniendo después de la etapa en curso...")

    def _run_worker(self, path):
        def on_progress(i, label):
            self.q.put(("progress", i, label))

        def should_stop():
            return self.stop_event.is_set()

        try:
            report = analyze_package(path, progress_cb=on_progress,
                                     should_stop=should_stop)
            if report is None:
                self.q.put(("stopped",))
            else:
                self.q.put(("done", report))
        except Exception as exc:
            self.q.put(("error", str(exc)))

    def _poll(self):
        try:
            while True:
                message = self.q.get_nowait()
                kind = message[0]

                if kind == "progress":
                    index, label = message[1], message[2]
                    self.progress["value"] = index + 1
                    self.status_var.set(label)

                elif kind == "stopped":
                    self.status_var.set("Análisis detenido por el usuario.")
                    self._reset_buttons()

                elif kind == "done":
                    self.report = message[1]
                    self.progress["value"] = len(STAGES) + 1
                    self.status_var.set("Análisis completado.")
                    self._display()
                    self.save_btn.configure(state="normal")
                    self._reset_buttons()

                elif kind == "error":
                    self.status_var.set("Error: " + str(message[1]))
                    self._reset_buttons()
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._poll)

    def _reset_buttons(self):
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def _display(self):
        report = self.report

        for item in self.components_tree.get_children():
            self.components_tree.delete(item)
        for row in component_rows(report):
            self.components_tree.insert("", "end", values=row)

        for item in self.vulnerabilities_tree.get_children():
            self.vulnerabilities_tree.delete(item)
        for row in vulnerability_rows(report):
            self.vulnerabilities_tree.insert("", "end", values=row)

        self.recommendations_text.delete("1.0", "end")
        self.recommendations_text.insert("1.0", "\n".join(
            recommendations(report)))

    def _save(self):
        if self.report is not None:
            _save_all(self.root, self.report)


def main():
    import tkinter as tk
    root = tk.Tk()
    PackageAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()