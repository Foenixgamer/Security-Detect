"""
SQS - Interfaz gráfica (tkinter, stdlib).

Dos modos:
    python sqs_gui.py <directorio_de_reportes>   -> visor de resultados
    python sqs_gui.py --app                       -> app interactiva
        Selecciona un archivo, ejecuta el pipeline de 7 capas con barra de
        progreso y pausa en zona AMBIGUO para decisión humana.

También exporta informe HTML (export_html).
"""

import json
import os
import queue
import sys
import threading

_REPORT_FILES = [
    ("classification", "classification.json"),
    ("static_analysis", "static_analysis.json"),
    ("dynamic_report", "dynamic_report.json"),
    ("verdict_map", "verdict_map.json"),
    ("surgery_report", "surgery_report.json"),
    ("surgery_log", "surgery_log.json"),
    ("integrity_verification", "integrity_verification.json"),
    ("rules_report", "rules_report.json"),
    ("rerun_dynamic_report", "rerun_dynamic_report.json"),
    ("final_report", "final_report.json"),
    ("manifest", "manifest.json"),
    ("complete_report", "complete_report.json"),
]

_CSS = """
body { font-family: Verdana, Arial, sans-serif; margin: 24px; }
h1 { color: #1f3a93; }
.verdict { font-size: 20px; font-weight: bold; padding: 8px;
           display: inline-block; border-radius: 6px; color: #fff; }
.seguro { background: #27ae60; }
.sospechoso { background: #f39c12; }
.malicioso { background: #c0392b; }
pre { background: #f5f5f5; padding: 10px; border-radius: 6px;
      overflow-x: auto; }
"""


def load_reports(report_dir):
    """Carga todos los reportes JSON disponibles en el directorio."""
    reports = {}
    for key, name in _REPORT_FILES:
        path = os.path.join(report_dir, name)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                reports[key] = json.load(f)
    return reports


def export_html(report_dir, dest=None):
    """Genera un informe HTML autocontenido con todos los reportes."""
    reports = load_reports(report_dir)
    dest = dest or os.path.join(report_dir, "sqs_report.html")

    classification = reports.get("classification") or {}
    verdict = classification.get("verdict", "sin datos")
    risk = classification.get("risk_score", 0)

    html = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>SQS Report</title><style>", _CSS, "</style></head><body>",
        "<h1>SQS - Informe de análisis</h1>",
        f"<p>Directorio: <code>{report_dir}</code></p>",
        f"<span class='verdict {verdict}'>Veredicto: {verdict}</span>",
        f"<p>Puntaje de riesgo: <b>{risk}</b></p>",
    ]

    threats = classification.get("threats_found", []) or []
    if threats:
        html.append("<h2>Amenazas detectadas</h2><ul>")
        html.extend(f"<li>{t}</li>" for t in threats)
        html.append("</ul>")

    final = reports.get("final_report") or {}
    summary = final.get("summary", []) or []
    if summary:
        html.append("<h2>Resumen final</h2><ul>")
        html.extend(f"<li>{t}</li>" for t in summary)
        html.append("</ul>")

    for key, name in _REPORT_FILES:
        if key in reports:
            html.append(f"<h2>{key}</h2>")
            html.append("<pre>")
            html.append(json.dumps(reports[key], indent=2,
                                   ensure_ascii=False, default=str))
            html.append("</pre>")

    html.append("</body></html>")

    with open(dest, "w", encoding="utf-8") as f:
        f.write("".join(html))
    return dest


def _viewer_widgets(parent, reports):
    """Construye listbox + texto dentro de `parent`."""
    import tkinter as tk
    from tkinter import ttk

    frame = tk.Frame(parent)
    listbox = tk.Listbox(frame, width=24, font=("Consolas", 10))
    listbox.pack(side="left", fill="y")

    text = tk.Text(frame, wrap="none", font=("Consolas", 9))
    text.pack(side="right", fill="both", expand=True)
    scroll = ttk.Scrollbar(frame, command=text.yview)
    scroll.pack(side="right", fill="y")
    text.config(yscrollcommand=scroll.set)

    stages = list(reports.keys())
    for stage in stages:
        listbox.insert("end", stage)

    def show_stage(_event=None):
        sel = listbox.curselection()
        if not sel:
            return
        key = stages[sel[0]]
        text.delete("1.0", "end")
        text.insert("1.0", json.dumps(reports[key], indent=2,
                                      ensure_ascii=False, default=str))

    listbox.bind("<<ListboxSelect>>", show_stage)
    if stages:
        listbox.selection_set(0)
        show_stage()

    frame.bind("<Configure>", lambda e: frame.pack_propagate(False))
    return frame


def launch_gui(report_dir):
    """Abre la ventana tkinter con los resultados del análisis."""
    import tkinter as tk
    from tkinter import ttk

    if not os.path.exists(report_dir):
        print(f"Directorio no encontrado: {report_dir}")
        sys.exit(1)

    reports = load_reports(report_dir)
    classification = reports.get("classification") or {}
    verdict = classification.get("verdict", "sin datos")
    risk = classification.get("risk_score", 0)
    threats = classification.get("threats_found", []) or []

    colors = {"seguro": "#27ae60", "sospechoso": "#f39c12",
              "malicioso": "#c0392b"}

    root = tk.Tk()
    root.title("SQS - Sanitizador Quirúrgico de Software")
    root.geometry("880x620")

    top = tk.Frame(root, bg="#f0f0f0", pady=10)
    top.pack(fill="x")

    tk.Label(top, text="VEREDICTO:", bg="#f0f0f0",
             font=("Verdana", 10)).pack(side="left", padx=8)
    tk.Label(top, text=verdict.upper(),
             bg=colors.get(verdict, "#7f8c8d"),
             fg="white", font=("Verdana", 12, "bold"),
             padx=10, pady=4).pack(side="left", padx=8)

    tk.Label(top, text=f"Riesgo: {risk}", bg="#f0f0f0",
             font=("Verdana", 10)).pack(side="left", padx=20)

    for t in threats:
        tk.Label(top, text="\u26a0 " + t, bg="#f0f0f0", fg="#c0392b",
                 font=("Verdana", 9)).pack(anchor="w", padx=20)

    main = _viewer_widgets(root, reports)
    main.pack(fill="both", expand=True, padx=8, pady=8)

    bottom = tk.Frame(root)
    bottom.pack(fill="x", pady=6)

    def do_export():
        from tkinter import filedialog, messagebox
        dest = filedialog.asksaveasfilename(
            title="Guardar informe HTML", defaultextension=".html",
            initialfile="sqs_report.html", filetypes=[("HTML", "*.html")])
        if dest:
            path = export_html(report_dir, dest)
            messagebox.showinfo("SQS", f"Informe generado:\n{path}")

    def open_export():
        import webbrowser
        dest = export_html(report_dir)
        webbrowser.open("file:///" + dest.replace("\\", "/"))

    ttk.Button(bottom, text="Exportar HTML...", command=do_export)\
        .pack(side="left", padx=8)
    ttk.Button(bottom, text="Abrir informe HTML", command=open_export)\
        .pack(side="left", padx=8)
    ttk.Button(bottom, text="Cerrar", command=root.destroy)\
        .pack(side="right", padx=8)

    root.mainloop()


DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".scr", ".com", ".pif", ".vbs",
    ".js", ".jse", ".wsf", ".ps1", ".dll",
}


class _App:
    """App interactiva: selección múltiple (archivos/directorios/ISO),
    análisis con progreso y decisión AMBIGUO en archivo único."""

    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk

        self.root = root
        self.q = queue.Queue()
        self.worker = None
        self.input_file = None
        self.result = None      # (package_dir, classification, temp_dir)
        self.selected_inputs = []
        self._scanning = False
        self._vt_scanning = False
        self._last_results = None

        root.title("SQS - Análisis interactivo")
        root.geometry("840x620")

        top = tk.Frame(root)
        top.pack(fill="x", padx=8, pady=8)

        tk.Label(top, text="Selección de entradas").pack(anchor="w")

        btns = tk.Frame(top)
        btns.pack(fill="x", pady=4)
        self.b_add_files = ttk.Button(btns, text="Seleccionar archivos",
                                      command=self._add_files)
        self.b_add_files.pack(side="left", padx=4)
        self.b_add_dir = ttk.Button(btns, text="Seleccionar directorios",
                                    command=self._add_dir)
        self.b_add_dir.pack(side="left", padx=4)
        self.b_add_iso = ttk.Button(btns, text="Seleccionar ISO",
                                    command=self._add_iso)
        self.b_add_iso.pack(side="left", padx=4)
        self.b_clear = ttk.Button(btns, text="Limpiar selección",
                                  command=self._clear_batch)
        self.b_clear.pack(side="left", padx=4)
        self.b_vaciar = ttk.Button(btns, text="Vaciar",
                                   command=self._vaciar)
        self.b_vaciar.pack(side="left", padx=4)

        tk.Label(top, text="Entradas seleccionadas:").pack(anchor="w")
        self._input_list = tk.Listbox(top, height=6)
        self._input_list.pack(fill="x")

        opts = tk.Frame(top)
        opts.pack(fill="x", pady=6)
        self.b_analyze = ttk.Button(opts, text="Analizar y procesar",
                                    command=self._analyze_all)
        self.b_analyze.pack(side="left")
        self.advanced_mode = tk.BooleanVar(value=False)
        tk.Checkbutton(opts, text="Modo avanzado: forzar cirugía en AMBIGUO",
                       variable=self.advanced_mode).pack(side="left",
                                                         padx=10)

        scan_row = tk.Frame(top)
        scan_row.pack(fill="x", pady=(0, 4))
        self.b_autoscan = ttk.Button(
            scan_row, text="Análisis automático (detectar malware)",
            command=self._start_auto_scan)
        self.b_autoscan.pack(side="left")

        self.status_var = tk.StringVar(value="Listo para análisis")
        self.status_label = tk.Label(top, textvariable=self.status_var,
                                     fg="blue", anchor="w")
        self.status_label.pack(fill="x", pady=(0, 4))

        vt = tk.LabelFrame(root, text="VirusTotal (verificación externa)")
        vt.pack(fill="x", padx=8, pady=(0, 6))

        vrow = tk.Frame(vt)
        vrow.pack(fill="x", padx=4, pady=4)
        tk.Label(vrow, text="API Key:").pack(side="left")
        self.vt_api_key = tk.StringVar(value=self._load_vt_key())
        tk.Entry(vrow, textvariable=self.vt_api_key, width=46,
                 show="*").pack(side="left", padx=6)
        self.b_vt_save = ttk.Button(vrow, text="Guardar",
                                    command=self._save_vt_key)
        self.b_vt_save.pack(side="left", padx=(0, 8))
        self.b_vt_scan = ttk.Button(vrow,
                                    text="Consultar VirusTotal",
                                    command=self._start_vt_scan)
        self.b_vt_scan.pack(side="left")

        urow = tk.Frame(vt)
        urow.pack(fill="x", padx=4, pady=(0, 4))
        tk.Label(urow, text="URL:").pack(side="left")
        self.vt_url_var = tk.StringVar(value="")
        tk.Entry(urow, textvariable=self.vt_url_var,
                 width=46).pack(side="left", padx=6)
        self.b_url_scan = ttk.Button(urow, text="Consultar URL",
                                     command=self._start_url_scan)
        self.b_url_scan.pack(side="left")

        self.progress = ttk.Progressbar(root, maximum=7)
        self.progress.pack(fill="x", padx=8, pady=(0, 8))

        self.log = tk.Text(root, height=10, state="disabled",
                           font=("Consolas", 9))
        self.log.pack(fill="x", padx=8)

        self.viewer_frame = tk.Frame(root)
        self.viewer_frame.pack(fill="both", expand=True, padx=8, pady=8)

        self.export_btn = ttk.Button(root, text="Abrir informe HTML",
                                     command=self._open_html, state="disabled")
        self.export_btn.pack(side="right", padx=8, pady=6)
        self.b_export_res = ttk.Button(
            root, text="Exportar resultados (JSON/CSV)",
            command=self._export_results)
        self.b_export_res.pack(side="right", padx=(0, 4), pady=6)

        self.root.after(100, self._poll)

    # --- helpers ---

    def _append_log(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_running(self, running):
        state = "disabled" if running else "normal"
        for w in (self.b_add_files, self.b_add_dir, self.b_add_iso,
                  self.b_analyze, self.b_autoscan, self.b_vt_save,
                  self.b_vt_scan, self.b_url_scan):
            w.configure(state=state)
        self.progress.configure(mode="determinate")

    # --- VirusTotal (conexión real, integrada por hash/subida) ---

    def _load_vt_key(self):
        from vt_connector import load_api_key
        return load_api_key()

    def _save_vt_key(self):
        from tkinter import messagebox
        from vt_connector import save_api_key
        key = self.vt_api_key.get().strip()
        if not key:
            messagebox.showwarning("Advertencia",
                                   "Ingresa una API Key válida.")
            return
        save_api_key(key)
        self._append_log("[+] API Key de VirusTotal guardada "
                         "(archivo local, no en el código).")
        messagebox.showinfo("Éxito", "API Key guardada correctamente")

    def _start_vt_scan(self):
        from tkinter import messagebox
        if not self.selected_inputs:
            self._append_log("[!] No hay entradas seleccionadas para "
                             "consultar en VirusTotal.")
            return
        api_key = self.vt_api_key.get().strip()
        if not api_key:
            messagebox.showwarning(
                "Advertencia", "Configura tu API Key de VirusTotal "
                "antes de consultar.")
            return
        self._set_running(True)
        self._vt_scanning = True
        self.status_var.set("Consultando VirusTotal...")
        self.status_label.configure(fg="orange")
        self._append_log(f"[+] VirusTotal: consultando "
                         f"{len(self.selected_inputs)} entrada(s).")
        paths = [e["path"] for e in self.selected_inputs]
        self.worker = threading.Thread(
            target=self._vt_scan_worker, args=(paths, api_key),
            daemon=True)
        self.worker.start()

    def _start_url_scan(self):
        from tkinter import messagebox
        url = self.vt_url_var.get().strip()
        if not url:
            self._append_log("[!] Ingresa una URL para consultar.")
            return
        api_key = self.vt_api_key.get().strip()
        if not api_key:
            messagebox.showwarning(
                "Advertencia", "Configura tu API Key de VirusTotal "
                "antes de consultar.")
            return
        self._set_running(True)
        self.status_var.set("Consultando URL en VirusTotal...")
        self.status_label.configure(fg="orange")
        self._append_log(f"[+] VirusTotal URL: {url}")
        self.worker = threading.Thread(
            target=self._url_scan_worker, args=(url, api_key),
            daemon=True)
        self.worker.start()

    def _url_scan_worker(self, url, api_key):
        from vt_connector import VTConfigError, VTError, scan_url
        from vt_connector import fetch_analysis
        try:
            analysis_id = scan_url(api_key, url)
            if not analysis_id:
                self.q.put(("error", None, None,
                            "VirusTotal URL: sin id de análisis"))
                return
            stats = fetch_analysis(api_key, analysis_id)
            self.q.put(("vt_url", None, None, (url, stats)))
        except (VTConfigError, VTError) as e:
            self.q.put(("error", None, None, f"VirusTotal URL: {e}"))

    def _export_results(self):
        import json as _json
        from tkinter import filedialog, messagebox
        if not self._last_results:
            messagebox.showwarning(
                "Advertencia", "No hay resultados exportables aún "
                "(finaliza un análisis/lote primero).")
            return
        out_dir = filedialog.askdirectory(
            title="Carpeta para exportar resultados")
        if not out_dir:
            return
        from batch_processor import _write_batch_report, write_csv_summary
        json_path = os.path.join(out_dir, "batch_report.json")
        csv_path = os.path.join(out_dir, "resumen_batch.csv")
        _write_batch_report(self._last_results, out_dir)
        write_csv_summary(self._last_results, csv_path)
        self._append_log(f"[+] Exportados: {json_path}")
        self._append_log(f"[+] Exportados: {csv_path}")
        messagebox.showinfo(
            "Exportación", f"Guardados en:\n{json_path}\n{csv_path}")

    def _vt_scan_worker(self, paths, api_key):
        from batch_processor import resolve_inputs
        from vt_connector import VTConfigError, VTError, analyze_file

        try:
            targets = resolve_inputs(paths)
        except Exception as e:
            self.q.put(("error", None, None, f"VirusTotal: {e}"))
            return
        if not targets:
            self.q.put(("error", None, None,
                        "VirusTotal: no hay archivos de interés"))
            return
        for i, target in enumerate(targets):
            try:
                res = analyze_file(api_key, target)
            except VTConfigError as e:
                self._append_log(f"[VT-ERROR] {e}")
                self.q.put(("vt_finished", None, None, None))
                return
            except VTError as e:
                self.q.put(("vt_file", None, None,
                            (target, "error", None, str(e))))
                continue
            verdict = "MALICIOSO" if res["malicious"] > 0 else (
                "SOSPECHOSO" if res["suspicious"] > 0 else "LIMIO")
            found = res["found"]
            self.q.put(("vt_file", None, None,
                        (target, verdict, found, res)))
        self.q.put(("vt_finished", None, None, None))

    def _vaciar(self):
        """Limpia entradas, log, visor y resultados: arranque limpio."""
        import tkinter as tk
        from tkinter import messagebox
        if not messagebox.askokcancel(
                "Vaciar", "Se limpiarán las entradas, el registro y los "
                "resultados. ¿Continuar?"):
            return
        self.selected_inputs = []
        self._refresh_list()
        self._scanning = False
        self.status_var.set("Listo para análisis")
        self.status_label.configure(fg="blue")
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        for child in self.viewer_frame.winfo_children():
            child.destroy()
        tk.Label(self.viewer_frame, text="Sin análisis previo.",
                 anchor="w", fg="gray").pack(anchor="w")
        self.progress["value"] = 0
        self.result = None
        self.export_btn.configure(state="disabled")
        self._append_log("[+] Campos vaciados. Listo para nueva entrada.")

    # --- selección unificada (archivos / directorios / ISO) ---

    def _refresh_list(self):
        self._input_list.delete(0, "end")
        for entry in self.selected_inputs:
            kind = entry["type"].upper()
            label = entry["path"] if entry["type"] == "dir" \
                else os.path.basename(entry["path"])
            self._input_list.insert("end", f"{kind}: {label}")

    def _add(self, paths, kind):
        for p in paths:
            if any(e["path"] == p for e in self.selected_inputs):
                continue
            self.selected_inputs.append({"type": kind, "path": p})
            if kind == "file" and os.path.splitext(p)[1].lower() in \
                    DANGEROUS_EXTENSIONS:
                self._append_log(f"[!] Extensión peligrosa: "
                                 f"{os.path.basename(p)}")
        self._refresh_list()

    def _add_files(self):
        from tkinter import filedialog
        paths = filedialog.askopenfilenames(title="Seleccionar archivos")
        self._add(paths, "file")

    def _add_dir(self):
        from tkinter import filedialog
        path = filedialog.askdirectory(title="Seleccionar directorio")
        if path:
            self._add([path], "dir")

    def _add_iso(self):
        from tkinter import filedialog
        paths = filedialog.askopenfilenames(
            title="Seleccionar archivos ISO",
            filetypes=[("Archivos ISO", "*.iso")])
        self._add(paths, "iso")

    def _clear_batch(self):
        if not self.selected_inputs:
            return
        from tkinter import messagebox
        if not messagebox.askokcancel(
                "Limpiar selección",
                "Se eliminarán TODAS las entradas seleccionadas. "
                "¿Continuar?"):
            return
        self.selected_inputs = []
        self._refresh_list()
        self._append_log("[+] Selección limpiada.")

    def _analyze_all(self):
        if not self.selected_inputs:
            self._append_log("[!] No hay entradas seleccionadas.")
            return
        self._set_running(True)
        self.progress["value"] = 0
        self._append_log(f"[+] Procesando {len(self.selected_inputs)} "
                         f"entrada(s)...")
        if (len(self.selected_inputs) == 1 and
                self.selected_inputs[0]["type"] == "file"):
            self.worker = threading.Thread(
                target=self._run_worker,
                args=(self.selected_inputs[0]["path"],), daemon=True)
        else:
            paths = [e["path"] for e in self.selected_inputs]
            self.worker = threading.Thread(
                target=self._batch_worker,
                args=(paths, self.advanced_mode.get()), daemon=True)
        self.worker.start()

    def _start_auto_scan(self):
        if not self.selected_inputs:
            self._append_log("[!] No hay entradas seleccionadas para "
                             "analizar.")
            return
        self._set_running(True)
        self.progress["value"] = 0
        self._scanning = True
        self.status_var.set("Analizando archivos... (detección, sin "
                            "modificar)")
        self.status_label.configure(fg="orange")
        self._append_log(f"[+] Análisis automático: "
                         f"{len(self.selected_inputs)} entrada(s).")
        paths = [e["path"] for e in self.selected_inputs]
        self.worker = threading.Thread(
            target=self._batch_worker, args=(paths, False, True),
            daemon=True)
        self.worker.start()

    def _batch_worker(self, paths, force=False, analyze_only=False):
        from batch_processor import process_batch

        def on_file_done(entry):
            status = entry["status"]
            verdict = (entry.get("classification") or {}).get(
                "verdict", "-")
            self.q.put(("batch_file", None, None,
                        (entry["input"], status, verdict,
                         entry.get("sanitized_file"), analyze_only)))

        cb = None
        if force:
            import sqs
            cb = lambda c, v=None: sqs.DECISION_FUERZA

        try:
            base = os.path.join(os.getcwd(), "sqs_batch_output")
            os.makedirs(base, exist_ok=True)
            results = process_batch(paths, base_dir=base,
                                    decision_callback=cb,
                                    analyze_only=analyze_only,
                                    on_file_done=on_file_done)
            self.q.put(("batch_finished", None, None, results))
        except Exception as e:
            self.q.put(("error", None, None, str(e)))

    # --- hilo del pipeline ---

    def _run_worker(self, path):
        import sqs

        def on_progress(i, label):
            self.q.put(("progress", i, label, None))
            self._append_log(f"[{i}/7] {label}")

        def on_decision(classification, verdict_map_path):
            self.q.put(("decision", None, None, classification))
            result = {"decision": sqs.DECISION_CONTINUAR}
            # espera la respuesta de la UI
            self.q.put(("decision_wait", None, None, result))
            return result["decision"]

        try:
            package, classification, temp_dir = sqs.run_pipeline(
                path, decision_callback=on_decision, on_progress=on_progress)
            self.result = (package, classification, temp_dir)
            self.q.put(("done", None, None, None))
        except Exception as e:
            self.q.put(("error", None, None, str(e)))

    def _poll(self):
        try:
            while True:
                kind, i, label, payload = self.q.get_nowait()

                if kind == "progress" and i is not None:
                    self.progress["value"] = i

                elif kind == "decision":
                    classification = payload
                    self._last_decision = _ask_decision(self.root,
                                                        classification)

                elif kind == "decision_wait":
                    result = payload
                    result["decision"] = getattr(
                        self, "_last_decision", "continuar")

                elif kind == "vt_file":
                    target, verdict, found, res = payload
                    name = os.path.basename(target)
                    if verdict == "error":
                        self._append_log(f"[VT-ERROR] {name}: {res}")
                    else:
                        src = "encontrado" if found else "subido a analizar"
                        ms = (res or {}).get("malicious", 0)
                        su = (res or {}).get("suspicious", 0)
                        und = (res or {}).get("undetected", 0)
                        line = (f"[VT {verdict:<10}] {name} [{src}] "
                                f"maliciosos={ms} sospechosos={su} "
                                f"sin-detectar={und}")
                        engines = (res or {}).get("engines") or []
                        if engines:
                            line += " motores: " + ", ".join(engines[:3])
                        self._append_log(line)
                    self.progress["value"] = min(
                        self.progress["value"] + 7, 7)

                elif kind == "vt_url":
                    url, stats = payload
                    self._set_running(False)
                    ms = stats.get("malicious", 0)
                    su = stats.get("suspicious", 0)
                    und = stats.get("undetected", 0)
                    verdict = ("MALICIOSA" if ms > 0 else
                               ("SOSPECHOSA" if su > 0 else "LIMIA"))
                    self._append_log(
                        f"[VT URL {verdict}] {url} | maliciosos={ms} "
                        f"sospechosos={su} sin-detectar={und}")
                    self.status_var.set("Consulta URL completada")
                    self.status_label.configure(fg="green")

                elif kind == "vt_finished":
                    self._vt_scanning = False
                    self._set_running(False)
                    self.status_var.set("Consulta a VirusTotal completada")
                    self.status_label.configure(fg="green")
                    self._append_log("[+] Consulta a VirusTotal finalizada.")

                elif kind == "done":
                    self._set_running(False)
                    self.progress["value"] = 7
                    self._append_log("[+] Análisis completado.")
                    self.status_var.set("Análisis completado")
                    self.status_label.configure(fg="green")
                    package, classification, temp_dir = self.result
                    self._last_results = [
                        self._entry_from_result(package, classification,
                                                temp_dir)]
                    self._show_results()
                    self.export_btn.configure(state="normal")

                elif kind == "batch_file":
                    inp, status, verdict, san, scanning = payload
                    if scanning:
                        tag = {"malicioso": "MALICIOSO",
                               "ambiguo": "SOSPECHOSO",
                               "benigno": "LIMIO"}.get(
                            verdict, verdict.upper())
                        self._append_log(f"[{tag:<11}] "
                                         f"{os.path.basename(inp)}")
                    else:
                        mark = ("OK " if status == "ok"
                                else status.upper())
                        self._append_log(
                            f"[{mark}] {os.path.basename(inp):<28} "
                            f"veredicto={verdict} "
                            f"sanitized={san or '-'}")
                    self.progress["value"] = min(
                        self.progress["value"] + 7, 7)

                elif kind == "batch_finished":
                    self._set_running(False)
                    results = payload
                    self._last_results = results
                    ok = [r for r in results if r["status"] == "ok"]
                    err = len(results) - len(ok)
                    mal = sum(1 for r in ok
                              if (r.get("classification") or {}).get(
                                  "zone") == "malicioso")
                    susp = sum(1 for r in ok
                               if (r.get("classification") or {}).get(
                                   "zone") == "ambiguo")
                    if self._scanning:
                        self._scanning = False
                        self._append_log(
                            f"[+] Análisis automático: {len(results)} "
                            f"archivos | maliciosos={mal} "
                            f"sospechosos={susp} errores={err}")
                        self.status_var.set("Análisis completado")
                        self.status_label.configure(fg="green")
                    else:
                        self._append_log(
                            f"[+] Lote terminado: {len(results)} archivos "
                            f"(maliciosos={mal}, sospechosos={susp}, "
                            f"errores={err}).")
                        self._append_log(
                            f"    resumen: {os.path.join(os.getcwd(), 'sqs_batch_output', 'batch_report.json')}")
                        self.export_btn.configure(state="normal")
                        last = next((r for r in ok
                                     if r.get("temp_dir")), None)
                        if last:
                            self.result = (last.get("package_dir"),
                                           last.get("classification"),
                                           last.get("temp_dir"))
                            self._show_results()

                elif kind == "error":
                    self._set_running(False)
                    self._append_log(f"[!] Error: {payload}")
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._poll)

    def _entry_from_result(self, package, classification, temp_dir):
        """Entrada tipo batch para exportar el resultado de un archivo."""
        import json
        entry = {"input": self.input_file or "", "status": "ok",
                 "classification": classification,
                 "package_dir": package, "temp_dir": temp_dir,
                 "surgery_status": None, "verification_status": None,
                 "sanitized_file": None, "error": None}
        sp = os.path.join(temp_dir, "surgery_report.json")
        if os.path.isfile(sp):
            try:
                with open(sp, encoding="utf-8") as f:
                    surgery = json.load(f)
                entry["surgery_status"] = surgery.get("surgery_status")
                sf = surgery.get("sanitized_file")
                if sf:
                    entry["sanitized_file"] = os.path.basename(sf)
            except Exception:
                pass
        vp = os.path.join(temp_dir, "integrity_verification.json")
        if os.path.isfile(vp):
            try:
                with open(vp, encoding="utf-8") as f:
                    entry["verification_status"] = json.load(f).get(
                        "verification_status")
            except Exception:
                pass
        return entry

    def _show_results(self):
        for child in self.viewer_frame.winfo_children():
            child.destroy()

        package, classification, temp_dir = self.result
        reports = load_reports(temp_dir)
        viewer = _viewer_widgets(self.viewer_frame, reports)
        viewer.pack(fill="both", expand=True)

        verdict = classification.get("verdict", "?")
        self._append_log(f"[+] Veredicto: {verdict} | "
                         f"datos: {temp_dir}")

    def _open_html(self):
        import webbrowser
        if self.result is None:
            return
        _, _, temp_dir = self.result
        dest = export_html(temp_dir)
        webbrowser.open("file:///" + dest.replace("\\", "/"))


def _ask_decision(root, classification):
    """Diálogo de pausa en zona AMBIGUO (decisión humana)."""
    import tkinter as tk

    verdict = classification.get("verdict", "sospechoso")
    threats = classification.get("threats_found", []) or []

    top = tk.Toplevel(root)
    top.title("Decisión requerida - Zona AMBIGUO")
    top.grab_set()

    tk.Label(top, text=("Zona AMBIGUO detectada."),
             font=("Verdana", 11, "bold")).pack(padx=16, pady=(12, 4))
    tk.Label(top, text=f"Veredicto: {verdict}",
             font=("Verdana", 10)).pack(padx=16)
    for t in threats[:5]:
        tk.Label(top, text="\u26a0 " + t, fg="#c0392b",
                 font=("Verdana", 9)).pack(anchor="w", padx=20)

    result = {"decision": "continuar"}

    def choose(decision):
        result["decision"] = decision
        top.destroy()

    buttons = tk.Frame(top)
    buttons.pack(pady=12)
    tk.Button(buttons, text="Continuar sin cirugía",
              command=lambda: choose("continuar")).pack(side="left", padx=4)
    tk.Button(buttons, text="Forzar cirugía",
              command=lambda: choose("fuerza_cirugia")).pack(side="left",
                                                             padx=4)
    tk.Button(buttons, text="Abortar",
              command=lambda: choose("abortar")).pack(side="left", padx=4)

    top.update_idletasks()
    top.deiconify()
    top.wait_window()

    return result["decision"]


def launch_app():
    """Lanzador de la app interactiva."""
    import tkinter as tk
    root = tk.Tk()
    _App(root)
    root.mainloop()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--app":
        launch_app()
    else:
        report_dir = sys.argv[1] if len(sys.argv) > 1 else os.getenv("TEMP_DIR", ".")
        launch_gui(report_dir)


if __name__ == "__main__":
    main()