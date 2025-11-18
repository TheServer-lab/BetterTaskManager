# better_task_manager_with_tree.py
import sys
import os
import datetime
from collections import deque, defaultdict
from functools import partial

import psutil
from PyQt5 import QtWidgets, QtCore, QtGui
import pyqtgraph as pg

REFRESH_INTERVAL_MS = 1000   # sampling interval
HISTORY_LENGTH = 120         # number of samples kept (~2 minutes at 1s)

# -------------------------
# Process Table Model
# -------------------------
class ProcessTableModel(QtCore.QAbstractTableModel):
    HEADERS = ["PID", "Name", "CPU %", "Mem %", "User", "Status", "Cmdline"]
    def __init__(self, parent=None):
        super().__init__(parent)
        self.process_rows = []  # list of dicts (psutil info)
        self.filter_text = ""

    def update_snapshot(self, filter_text=""):
        self.filter_text = (filter_text or "").strip().lower()
        procs = []
        for p in psutil.process_iter(['pid','name','username','status','cmdline']):
            try:
                info = p.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            # try to get instantaneous cpu/mem (may raise)
            try:
                info['cpu_percent'] = p.cpu_percent(interval=None)
                info['memory_percent'] = p.memory_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                info['cpu_percent'] = 0.0
                info['memory_percent'] = 0.0
            # filtering
            if self.filter_text:
                ft = self.filter_text
                hay = f"{info.get('pid','')} {info.get('name','') or ''} {' '.join(info.get('cmdline') or [])}".lower()
                if ft not in hay:
                    continue
            procs.append(info)
        procs.sort(key=lambda x: (-x.get('cpu_percent',0), str(x.get('name',''))))
        self.beginResetModel()
        self.process_rows = procs
        self.endResetModel()

    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self.process_rows)

    def columnCount(self, parent=QtCore.QModelIndex()):
        return len(self.HEADERS)

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.process_rows[index.row()]
        col = index.column()
        if role == QtCore.Qt.DisplayRole:
            if col == 0: return str(row.get('pid',''))
            if col == 1: return row.get('name','') or ""
            if col == 2: return f"{row.get('cpu_percent',0):.1f}"
            if col == 3: return f"{row.get('memory_percent',0):.1f}"
            if col == 4: return row.get('username','') or ""
            if col == 5: return row.get('status','') or ""
            if col == 6:
                return " ".join(row.get('cmdline') or [])[:240]
        if role == QtCore.Qt.TextAlignmentRole:
            if col in (0,2,3):
                return QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter
        return None

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role != QtCore.Qt.DisplayRole: return None
        if orientation == QtCore.Qt.Horizontal:
            return self.HEADERS[section]
        return int(section+1)

    def get_pid_at_row(self, row):
        try:
            return int(self.process_rows[row]['pid'])
        except Exception:
            return None

# -------------------------
# Main Window
# -------------------------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Better Task Manager — Tree + Per-Process Graphs")
        self.resize(1200, 780)

        # central widget
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QVBoxLayout(central)

        # top controls
        top_h = QtWidgets.QHBoxLayout()
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText("Filter PID / name / cmdline ... (press Enter or wait)")
        self.search.returnPressed.connect(self.manual_refresh)
        self.auto_refresh_checkbox = QtWidgets.QCheckBox("Auto-refresh")
        self.auto_refresh_checkbox.setChecked(True)
        btn_refresh = QtWidgets.QPushButton("Refresh now")
        btn_refresh.clicked.connect(self.manual_refresh)
        top_h.addWidget(self.search)
        top_h.addWidget(self.auto_refresh_checkbox)
        top_h.addWidget(btn_refresh)
        main_layout.addLayout(top_h)

        # main splitter: left=tree, center=table, right=details+graphs
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        main_layout.addWidget(splitter, 1)

        # LEFT: process tree
        left_w = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_w)
        left_label = QtWidgets.QLabel("Process Tree")
        left_layout.addWidget(left_label)
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(["PID", "Name", "CPU%", "Mem%"])
        self.tree.itemClicked.connect(self.on_tree_item_clicked)
        left_layout.addWidget(self.tree, 1)
        splitter.addWidget(left_w)
        splitter.setStretchFactor(0, 1)

        # CENTER: table
        self.model = ProcessTableModel()
        self.table = QtWidgets.QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QtWidgets.QTableView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QTableView.SingleSelection)
        self.table.doubleClicked.connect(self.on_table_doubleclick)
        self.table.selectionModel().selectionChanged.connect(self.on_table_selection_changed)
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.table_context_menu)
        table_container = QtWidgets.QWidget()
        table_layout = QtWidgets.QVBoxLayout(table_container)
        table_layout.addWidget(QtWidgets.QLabel("Process List"))
        table_layout.addWidget(self.table)
        splitter.addWidget(table_container)
        splitter.setStretchFactor(1, 2)

        # RIGHT: details and graphs
        right_w = QtWidgets.QWidget()
        rv = QtWidgets.QVBoxLayout(right_w)
        rv.addWidget(QtWidgets.QLabel("Details / Per-process Graphs"))
        self.detail_text = QtWidgets.QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFixedHeight(200)
        rv.addWidget(self.detail_text)

        # per-process graphs (cpu + mem)
        self.cpu_plot = pg.PlotWidget(title="Process CPU %")
        self.mem_plot = pg.PlotWidget(title="Process Memory %")
        self.cpu_plot.setLabel('left', 'CPU %')
        self.cpu_plot.setLabel('bottom', 'Samples (latest to right)')
        self.mem_plot.setLabel('left', 'Memory %')
        rv.addWidget(self.cpu_plot, 1)
        rv.addWidget(self.mem_plot, 1)

        # action buttons
        actions_h = QtWidgets.QHBoxLayout()
        btn_kill = QtWidgets.QPushButton("Kill")
        btn_suspend = QtWidgets.QPushButton("Suspend")
        btn_resume = QtWidgets.QPushButton("Resume")
        btn_setprio = QtWidgets.QPushButton("Set Priority")
        btn_open_folder = QtWidgets.QPushButton("Open Executable Folder")
        btn_kill.clicked.connect(self.action_kill)
        btn_suspend.clicked.connect(self.action_suspend)
        btn_resume.clicked.connect(self.action_resume)
        btn_setprio.clicked.connect(self.action_set_priority)
        btn_open_folder.clicked.connect(self.action_open_folder)
        actions_h.addWidget(btn_kill)
        actions_h.addWidget(btn_suspend)
        actions_h.addWidget(btn_resume)
        actions_h.addWidget(btn_setprio)
        actions_h.addWidget(btn_open_folder)
        actions_h.addStretch()
        rv.addLayout(actions_h)

        splitter.addWidget(right_w)
        splitter.setStretchFactor(2, 2)

        # history storage: pid -> deque of floats
        self.per_pid_cpu = defaultdict(lambda: deque(maxlen=HISTORY_LENGTH))
        self.per_pid_mem = defaultdict(lambda: deque(maxlen=HISTORY_LENGTH))
        # keep track of last-seen pids to prune histories
        self.known_pids = set()

        # plotting curves
        self.cpu_curve = self.cpu_plot.plot()
        self.mem_curve = self.mem_plot.plot()

        # timer for periodic refresh
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self._on_timer)
        self.timer.start(REFRESH_INTERVAL_MS)

        # initial population
        self.refresh_all()

    # -------------------------
    # Refresh / sampling
    # -------------------------
    def manual_refresh(self):
        self.refresh_all(force=True)

    def _on_timer(self):
        if not self.auto_refresh_checkbox.isChecked():
            return
        self.refresh_all()

    def refresh_all(self, force=False):
        filter_text = self.search.text().strip()
        # update table snapshot
        self.model.update_snapshot(filter_text)
        # update tree and histories & global system sampling
        self._sample_processes()
        self._rebuild_tree()
        # update details for selected
        pid = self.get_selected_pid()
        if pid:
            self.fill_process_details(pid)
            self.update_per_process_plots(pid)
        else:
            self.detail_text.setPlainText("Select a process (table or tree) to view details and per-process graphs.")
            self.cpu_curve.setData([])
            self.mem_curve.setData([])

    def _sample_processes(self):
        """
        Sample CPU and memory for each visible process and maintain per-pid history.
        """
        current_pids = set()
        # We'll iterate all processes (costly but acceptable usually) and sample stats
        for p in psutil.process_iter(['pid','name']):
            pid = p.pid
            current_pids.add(pid)
            # get cpu% and memory% (non-blocking; cpu_percent returns since last call)
            try:
                cpu = p.cpu_percent(interval=None)
                mem = p.memory_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cpu = 0.0
                mem = 0.0
            self.per_pid_cpu[pid].append(cpu)
            self.per_pid_mem[pid].append(mem)
        # prune histories of dead pids (to free memory)
        dead = set(self.per_pid_cpu.keys()) - current_pids
        for d in dead:
            del self.per_pid_cpu[d]
            del self.per_pid_mem[d]
        self.known_pids = current_pids

    # -------------------------
    # Process Tree
    # -------------------------
    def _rebuild_tree(self):
        """
        Build mapping parent_pid -> [child_pids] and show a QTreeWidget.
        """
        # collect processes snapshot quickly
        proc_info = {}
        for p in psutil.process_iter(['pid','name','ppid','cpu_percent','memory_percent']):
            try:
                info = p.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            proc_info[info['pid']] = info

        children_map = defaultdict(list)
        root_pids = []
        for pid, info in proc_info.items():
            ppid = info.get('ppid') or 0
            if ppid in proc_info:
                children_map[ppid].append(pid)
            else:
                root_pids.append(pid)

        # helper to create QTreeWidgetItem recursively
        self.tree.clear()
        def make_item(pid):
            info = proc_info.get(pid, {})
            name = info.get('name') or ""
            cpu = info.get('cpu_percent', 0.0)
            mem = info.get('memory_percent', 0.0)
            item = QtWidgets.QTreeWidgetItem([str(pid), name, f"{cpu:.1f}", f"{mem:.1f}"])
            item.setData(0, QtCore.Qt.UserRole, pid)
            for child_pid in sorted(children_map.get(pid, [])):
                child_item = make_item(child_pid)
                item.addChild(child_item)
            return item

        for pid in sorted(root_pids):
            try:
                item = make_item(pid)
                self.tree.addTopLevelItem(item)
            except Exception:
                continue
        self.tree.expandToDepth(0)  # collapsed by default, top-level visible

    # -------------------------
    # Selection sync & details
    # -------------------------
    def on_table_doubleclick(self, index):
        pid = self.model.get_pid_at_row(index.row())
        if pid:
            self.fill_process_details(pid)
            self.select_pid_in_tree(pid)

    def on_table_selection_changed(self, selected, _deselected):
        # when table selection changes, update detail/plots
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        pid = self.model.get_pid_at_row(rows[0].row())
        if pid:
            self.fill_process_details(pid)
            self.update_per_process_plots(pid)
            self.select_pid_in_tree(pid)

    def on_tree_item_clicked(self, item, _col):
        pid = item.data(0, QtCore.Qt.UserRole)
        if pid:
            self.fill_process_details(pid)
            self.update_per_process_plots(pid)
            self.select_pid_in_table(pid)

    def select_pid_in_tree(self, pid):
        # iterate items to find pid (recursive)
        it = QtWidgets.QTreeWidgetItemIterator(self.tree)
        while it.value():
            item = it.value()
            if item.data(0, QtCore.Qt.UserRole) == pid:
                self.tree.setCurrentItem(item)
                # ensure visible
                parent = item.parent()
                while parent:
                    parent.setExpanded(True)
                    parent = parent.parent()
                return
            it = it + 1

    def select_pid_in_table(self, pid):
        # find row in model
        for row_idx, r in enumerate(self.model.process_rows):
            try:
                if int(r.get('pid')) == int(pid):
                    self.table.selectRow(row_idx)
                    self.table.scrollTo(self.model.index(row_idx, 0), QtWidgets.QAbstractItemView.PositionAtCenter)
                    return
            except Exception:
                continue

    def get_selected_pid(self):
        # prioritize table selection, then tree
        rows = self.table.selectionModel().selectedRows()
        if rows:
            return self.model.get_pid_at_row(rows[0].row())
        cur = self.tree.currentItem()
        if cur:
            return cur.data(0, QtCore.Qt.UserRole)
        return None

    def fill_process_details(self, pid):
        try:
            p = psutil.Process(pid)
            info = p.as_dict(attrs=['pid','name','exe','cmdline','username','create_time','cpu_percent','memory_percent','status','num_threads','io_counters','connections','ppid'])
        except psutil.NoSuchProcess:
            self.detail_text.setPlainText("Process no longer exists.")
            return
        except Exception as e:
            self.detail_text.setPlainText(f"Could not read process info: {e}")
            return
        lines = []
        lines.append(f"PID: {info.get('pid')}")
        lines.append(f"Name: {info.get('name')}")
        exe = info.get('exe')
        if exe:
            lines.append(f"Executable: {exe}")
        cmd = info.get('cmdline') or []
        if cmd:
            lines.append("Cmdline: " + " ".join(cmd))
        lines.append(f"User: {info.get('username')}")
        ct = info.get('create_time')
        if ct:
            lines.append("Started: " + datetime.datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S"))
        lines.append(f"CPU %: {info.get('cpu_percent')}")
        lines.append(f"Memory %: {info.get('memory_percent')}")
        lines.append(f"Status: {info.get('status')}")
        lines.append(f"Threads: {info.get('num_threads')}")
        ppid = info.get('ppid')
        if ppid is not None:
            lines.append(f"Parent PID: {ppid}")
        io = info.get('io_counters')
        if io:
            lines.append(f"I/O - read: {getattr(io,'read_bytes',None)} bytes, write: {getattr(io,'write_bytes',None)} bytes")
        conns = info.get('connections')
        if conns:
            try:
                lines.append(f"Connections: {len(conns)}")
            except Exception:
                pass
        self.detail_text.setPlainText("\n".join(lines))

    # -------------------------
    # Per-process plotting
    # -------------------------
    def update_per_process_plots(self, pid):
        """
        Draw the per-pid history. If not available, show empty.
        """
        cpu_series = list(self.per_pid_cpu.get(pid, []))
        mem_series = list(self.per_pid_mem.get(pid, []))
        if cpu_series:
            self.cpu_curve.setData(cpu_series)
            self.cpu_plot.setTitle(f"Process CPU % — PID {pid}")
            self.cpu_plot.enableAutoRange(axis='y')
        else:
            self.cpu_curve.setData([])
            self.cpu_plot.setTitle(f"Process CPU % — PID {pid} (no data)")

        if mem_series:
            self.mem_curve.setData(mem_series)
            self.mem_plot.setTitle(f"Process Memory % — PID {pid}")
            self.mem_plot.enableAutoRange(axis='y')
        else:
            self.mem_curve.setData([])
            self.mem_plot.setTitle(f"Process Memory % — PID {pid} (no data)")

    # -------------------------
    # Context menu & actions
    # -------------------------
    def table_context_menu(self, pos):
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        pid = self.model.get_pid_at_row(idx.row())
        menu = QtWidgets.QMenu()
        act_kill = menu.addAction("Kill")
        act_suspend = menu.addAction("Suspend")
        act_resume = menu.addAction("Resume")
        act_details = menu.addAction("Show Details")
        act_open_folder = menu.addAction("Open Executable Folder")
        action = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if action == act_kill:
            self._perform_kill(pid)
        elif action == act_suspend:
            self._perform_suspend(pid)
        elif action == act_resume:
            self._perform_resume(pid)
        elif action == act_details:
            self.fill_process_details(pid)
        elif action == act_open_folder:
            self._open_exe_folder(pid)
        self.refresh_all()

    def action_kill(self):
        pid = self.get_selected_pid()
        if pid:
            self._perform_kill(pid)
            self.refresh_all()

    def action_suspend(self):
        pid = self.get_selected_pid()
        if pid:
            self._perform_suspend(pid)
            self.refresh_all()

    def action_resume(self):
        pid = self.get_selected_pid()
        if pid:
            self._perform_resume(pid)
            self.refresh_all()

    def action_set_priority(self):
        pid = self.get_selected_pid()
        if not pid:
            QtWidgets.QMessageBox.information(self, "No selection", "Select a process first.")
            return
        choices = ["low", "below_normal", "normal", "above_normal", "high", "realtime"]
        choice, ok = QtWidgets.QInputDialog.getItem(self, "Set process priority", "Priority:", choices, 2, False)
        if not ok:
            return
        try:
            p = psutil.Process(pid)
            # map choice to nice values depending on platform
            if sys.platform.startswith("win"):
                mapping = {
                    "low": psutil.IDLE_PRIORITY_CLASS,
                    "below_normal": psutil.BELOW_NORMAL_PRIORITY_CLASS,
                    "normal": psutil.NORMAL_PRIORITY_CLASS,
                    "above_normal": psutil.ABOVE_NORMAL_PRIORITY_CLASS,
                    "high": psutil.HIGH_PRIORITY_CLASS,
                    "realtime": psutil.REALTIME_PRIORITY_CLASS
                }
                p.nice(mapping[choice])
            else:
                # Unix nice: larger nice -> lower priority; map a couple values
                mapping = {
                    "low": 19,
                    "below_normal": 10,
                    "normal": 0,
                    "above_normal": -5,
                    "high": -10,
                    "realtime": -20
                }
                p.nice(mapping[choice])
            QtWidgets.QMessageBox.information(self, "Priority", f"Set priority of {pid} to {choice}.")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Could not set priority: {e}")

    def action_open_folder(self):
        pid = self.get_selected_pid()
        if pid:
            self._open_exe_folder(pid)

    def _perform_kill(self, pid):
        try:
            p = psutil.Process(pid)
            p.kill()
            QtWidgets.QMessageBox.information(self, "Killed", f"Process {pid} killed.")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Failed to kill {pid}:\n{e}")

    def _perform_suspend(self, pid):
        try:
            p = psutil.Process(pid)
            p.suspend()
            QtWidgets.QMessageBox.information(self, "Suspended", f"Process {pid} suspended.")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Failed to suspend {pid}:\n{e}")

    def _perform_resume(self, pid):
        try:
            p = psutil.Process(pid)
            p.resume()
            QtWidgets.QMessageBox.information(self, "Resumed", f"Process {pid} resumed.")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Failed to resume {pid}:\n{e}")

    def _open_exe_folder(self, pid):
        try:
            p = psutil.Process(pid)
            exe = p.exe()
            if not exe:
                raise RuntimeError("Executable path not available.")
            folder = os.path.dirname(exe)
            if sys.platform.startswith('win'):
                os.startfile(folder)
            elif sys.platform.startswith('linux'):
                QtCore.QProcess.startDetached('xdg-open', [folder])
            elif sys.platform.startswith('darwin'):
                QtCore.QProcess.startDetached('open', [folder])
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Could not open folder: {e}")

# -------------------------
# App entrypoint
# -------------------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    # small style nicety for high-DPI systems
    if hasattr(QtCore.Qt, 'AA_EnableHighDpiScaling'):
        app.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
