# better_task_manager_with_overview.py
"""
Better Task Manager — System Overview + Processes
Includes:
- Process tree + table
- Per-process graphs (CPU, Memory, GPU memory MB best-effort, Disk I/O KB/s, Active connections)
- System Overview tab with stacked CPU / Memory / GPU % graphs (Layout 1)
- Keeps selected process (PID) selected across refreshes
- GPU: tries pynvml then nvidia-smi as fallback, otherwise hides GPU plot / shows N/A
Dependencies: psutil, PyQt5, pyqtgraph. pynvml optional.
Run: python better_task_manager_with_overview.py
"""

import sys
import os
import time
import subprocess
import datetime
import shutil
from collections import deque, defaultdict

import psutil
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import *
import pyqtgraph as pg

# -------------------------
# Configuration
# -------------------------
REFRESH_INTERVAL_MS = 1000
HISTORY_LENGTH = 180  # samples (~3 minutes at 1s)

# -------------------------
# GPU backend detection: try pynvml, fallback to nvidia-smi, else None
# -------------------------
GPU_BACKEND = None
try:
    import pynvml
    pynvml.nvmlInit()
    GPU_BACKEND = "pynvml"
except Exception:
    # try nvidia-smi (we'll call it when needed)
    if shutil.which("nvidia-smi"):
        GPU_BACKEND = "nvidia-smi"
    else:
        GPU_BACKEND = None

def query_nvidia_smi_pid_usedmem():
    """Return mapping pid -> used GPU memory MB via nvidia-smi (best-effort)."""
    out = {}
    try:
        cmd = ["nvidia-smi", "--query-compute-apps=pid,used_memory", "--format=csv,noheader,nounits"]
        sp = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        if sp.returncode != 0 or not sp.stdout.strip():
            return {}
        for line in sp.stdout.splitlines():
            try:
                pid_str, mem_str = [x.strip() for x in line.split(",", 1)]
                pid = int(pid_str)
                mem_mb = float(mem_str)
                out[pid] = out.get(pid, 0.0) + mem_mb
            except Exception:
                continue
    except Exception:
        pass
    return out

def get_gpu_process_memory_map():
    """Return dict pid -> GPU memory MB (best-effort)."""
    mapping = {}
    if GPU_BACKEND == "pynvml":
        try:
            count = pynvml.nvmlDeviceGetCount()
            for i in range(count):
                try:
                    handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                    # try graphics processes (some wrappers expose this)
                    try:
                        plist = pynvml.nvmlDeviceGetGraphicsRunningProcesses(handle)
                    except AttributeError:
                        try:
                            plist = pynvml.nvmlDeviceGetComputeRunningProcesses(handle)
                        except Exception:
                            plist = []
                    except Exception:
                        plist = []
                    for pinfo in plist:
                        pid = getattr(pinfo, "pid", None)
                        mem = getattr(pinfo, "usedGpuMemory", None) \
                              or getattr(pinfo, "used_memory", None) \
                              or getattr(pinfo, "memoryUsed", None)
                        if pid is None or mem is None:
                            continue
                        try:
                            val = float(mem)
                            if val > 1024 * 1024 * 2:
                                val = val / (1024 * 1024)
                        except Exception:
                            val = 0.0
                        mapping[int(pid)] = mapping.get(int(pid), 0.0) + val
                except Exception:
                    continue
        except Exception:
            mapping = {}
    elif GPU_BACKEND == "nvidia-smi":
        mapping = query_nvidia_smi_pid_usedmem()
    return mapping

def get_gpu_total_util_percent():
    """Return GPU utilization percent (first GPU) or None if not available."""
    if GPU_BACKEND == "pynvml":
        try:
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            util = pynvml.nvmlDeviceGetUtilizationRates(handle)
            return float(getattr(util, "gpu", 0.0))
        except Exception:
            return None
    elif GPU_BACKEND == "nvidia-smi":
        try:
            sp = subprocess.run(["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
                                capture_output=True, text=True, timeout=1)
            if sp.returncode == 0 and sp.stdout.strip():
                try:
                    return float(sp.stdout.splitlines()[0].strip())
                except Exception:
                    return None
        except Exception:
            return None
    return None

# -------------------------
# Helper: safe psutil calls wrapper used below
# -------------------------
def safe_proc_iter(attrs):
    for p in psutil.process_iter(attrs):
        try:
            yield p
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

# -------------------------
# Process Table Model
# -------------------------
class ProcessTableModel(QtCore.QAbstractTableModel):
    HEADERS = ["PID", "Name", "CPU %", "Mem %", "User", "Status", "Cmdline"]
    def __init__(self, parent=None):
        super().__init__(parent)
        self.process_rows = []
        self.filter_text = ""

    def update_snapshot(self, filter_text=""):
        self.filter_text = (filter_text or "").strip().lower()
        rows = []
        for p in safe_proc_iter(['pid','name','username','status','cmdline']):
            try:
                info = p.info
            except Exception:
                continue
            try:
                info['cpu_percent'] = p.cpu_percent(interval=None)
                info['memory_percent'] = p.memory_percent()
            except Exception:
                info['cpu_percent'] = 0.0
                info['memory_percent'] = 0.0
            if self.filter_text:
                hay = f"{info.get('pid','')} {info.get('name','') or ''} {' '.join(info.get('cmdline') or [])}".lower()
                if self.filter_text not in hay:
                    continue
            rows.append(info)
        rows.sort(key=lambda x: (-x.get('cpu_percent',0), str(x.get('name',''))))
        self.beginResetModel()
        self.process_rows = rows
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
        self.setWindowTitle("Better Task Manager — System Overview + Processes")
        self.resize(1300, 860)

        # central widget = tabs
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        central_l = QtWidgets.QVBoxLayout(central)

        self.tabs = QtWidgets.QTabWidget()
        central_l.addWidget(self.tabs)

        # -------------------------
        # Tab 1: Processes (existing UI)
        # -------------------------
        self.processes_tab = QtWidgets.QWidget()
        proc_layout = QtWidgets.QVBoxLayout(self.processes_tab)

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
        proc_layout.addLayout(top_h)

        # main splitter inside Processes tab
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        proc_layout.addWidget(splitter, 1)

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

        # CENTER: process table
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

        # RIGHT: details and per-process graphs
        right_w = QtWidgets.QWidget()
        rv = QtWidgets.QVBoxLayout(right_w)
        rv.addWidget(QtWidgets.QLabel("Details / Per-process Graphs"))
        self.detail_text = QtWidgets.QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFixedHeight(220)
        rv.addWidget(self.detail_text)

        # per-process graphs
        self.cpu_plot = pg.PlotWidget(title="Process CPU %")
        self.mem_plot = pg.PlotWidget(title="Process Memory %")
        self.gpu_plot = pg.PlotWidget(title="Process GPU Memory (MB)")
        self.io_plot = pg.PlotWidget(title="Process Disk I/O KB/s (read, write)")
        self.conn_plot = pg.PlotWidget(title="Process Active Connections (count)")

        rv.addWidget(self.cpu_plot, 1)
        rv.addWidget(self.mem_plot, 1)
        rv.addWidget(self.gpu_plot, 1)
        rv.addWidget(self.io_plot, 1)
        rv.addWidget(self.conn_plot, 1)

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

        self.tabs.addTab(self.processes_tab, "Processes")

        # -------------------------
        # Tab 2: System Overview (stacked vertical)
        # -------------------------
        self.system_tab = QtWidgets.QWidget()
        sys_layout = QtWidgets.QVBoxLayout(self.system_tab)

        sys_layout.addWidget(QtWidgets.QLabel("System Overview (total resources)"))

        # System plots: stacked vertical (Layout 1)
        self.sys_cpu_plot = pg.PlotWidget(title="System CPU %")
        self.sys_mem_plot = pg.PlotWidget(title="System Memory %")
        self.sys_gpu_plot = pg.PlotWidget(title="System GPU % (if available)")

        # fixed y-range for CPU/RAM: 0-100%
        self.sys_cpu_plot.setYRange(0, 100)
        self.sys_mem_plot.setYRange(0, 100)
        self.sys_gpu_plot.setYRange(0, 100)

        sys_layout.addWidget(self.sys_cpu_plot, 1)
        sys_layout.addWidget(self.sys_mem_plot, 1)
        # GPU plot only added if backend available; add now but we may hide later
        sys_layout.addWidget(self.sys_gpu_plot, 1)

        self.tabs.addTab(self.system_tab, "System Overview")

        # -------------------------
        # Data structures: histories
        # -------------------------
        self.sys_cpu_hist = deque(maxlen=HISTORY_LENGTH)
        self.sys_mem_hist = deque(maxlen=HISTORY_LENGTH)
        self.sys_gpu_hist = deque(maxlen=HISTORY_LENGTH)  # percent or None
        self.x_axis = list(range(-HISTORY_LENGTH+1, 1))

        # per-pid histories
        self.per_pid_cpu = defaultdict(lambda: deque(maxlen=HISTORY_LENGTH))
        self.per_pid_mem = defaultdict(lambda: deque(maxlen=HISTORY_LENGTH))
        self.per_pid_gpu = defaultdict(lambda: deque(maxlen=HISTORY_LENGTH))
        self.per_pid_io_read = defaultdict(lambda: deque(maxlen=HISTORY_LENGTH))
        self.per_pid_io_write = defaultdict(lambda: deque(maxlen=HISTORY_LENGTH))
        self.per_pid_conns = defaultdict(lambda: deque(maxlen=HISTORY_LENGTH))

        # last counters for I/O delta
        self._last_proc_io = {}
        self.known_pids = set()

        # plotting curves: system
        self.sys_cpu_curve = self.sys_cpu_plot.plot(pen=pg.mkPen(width=2))
        self.sys_mem_curve = self.sys_mem_plot.plot(pen=pg.mkPen(width=2))
        self.sys_gpu_curve = self.sys_gpu_plot.plot(pen=pg.mkPen(width=2))

        # plotting curves: per-process
        self.cpu_curve = self.cpu_plot.plot()
        self.mem_curve = self.mem_plot.plot()
        self.gpu_curve = self.gpu_plot.plot()
        self.io_read_curve = self.io_plot.plot(pen=pg.mkPen(width=2))
        self.io_write_curve = self.io_plot.plot(pen=pg.mkPen(width=2, style=QtCore.Qt.DashLine))
        self.conn_curve = self.conn_plot.plot()

        # timer
        self.timer = QtCore.QTimer()
        self.timer.setInterval(REFRESH_INTERVAL_MS)
        self.timer.timeout.connect(self._on_timer)
        self.timer.start()

        # initial refresh/populate
        self.refresh_all(force=True)

        # Hide/annotate GPU system plot if no backend detected
        if GPU_BACKEND is None:
            self.sys_gpu_plot.setTitle("System GPU % (no GPU API detected)")
            # optionally hide: self.sys_gpu_plot.hide()

    # -------------------------
    # Keep/restore selection helper
    # -------------------------
    def restore_selection(self, pid):
        """Restore selection for both table and tree to a given PID (if still present)."""
        if pid is None:
            return
        # Restore table selection
        try:
            for row in range(self.model.rowCount()):
                if self.model.get_pid_at_row(row) == pid:
                    self.table.selectRow(row)
                    # ensure visible
                    self.table.scrollTo(self.model.index(row, 0), QtWidgets.QAbstractItemView.PositionAtCenter)
                    break
        except Exception:
            pass

        # Restore tree selection (search recursively)
        try:
            items = self.tree.findItems(str(pid), QtCore.Qt.MatchExactly | QtCore.Qt.MatchRecursive, 0)
            if items:
                item = items[0]
                self.tree.setCurrentItem(item)
                # expand parents
                parent = item.parent()
                while parent:
                    parent.setExpanded(True)
                    parent = parent.parent()
        except Exception:
            pass

    # -------------------------
    # Refresh / sampling (preserve selection)
    # -------------------------
    def manual_refresh(self):
        self.refresh_all(force=True)

    def _on_timer(self):
        if not self.auto_refresh_checkbox.isChecked():
            return
        self.refresh_all()

    def refresh_all(self, force=False):
        # --- remember current pid ---
        old_pid = self.get_selected_pid()

        # snapshot table
        filter_text = self.search.text().strip()
        self.model.update_snapshot(filter_text)

        # sample processes and system metrics
        self._sample_processes()
        self._rebuild_tree()

        # restore selection if still alive
        self.restore_selection(old_pid)

        # update system overview plotting
        self._update_system_plots()

        # update selected process details/plots if any
        pid = self.get_selected_pid()
        if pid:
            self.fill_process_details(pid)
            self.update_per_process_plots(pid)
        else:
            self.detail_text.setPlainText("Select a process (table or tree) to view details and per-process graphs.")
            self.cpu_curve.setData([])
            self.mem_curve.setData([])
            self.gpu_curve.setData([])
            self.io_read_curve.setData([])
            self.io_write_curve.setData([])
            self.conn_curve.setData([])

    def _sample_processes(self):
        """Sample system & per-process stats and update histories."""
        now = time.time()

        # System metrics
        sys_cpu = psutil.cpu_percent(interval=None)
        sys_mem = psutil.virtual_memory().percent
        self.sys_cpu_hist.append(sys_cpu)
        self.sys_mem_hist.append(sys_mem)

        # GPU total utilization percent (best-effort)
        gpu_util = get_gpu_total_util_percent()
        if gpu_util is None:
            # append 0 to keep same length but we may hide graph
            self.sys_gpu_hist.append(0.0)
        else:
            self.sys_gpu_hist.append(gpu_util)

        # Get per-process GPU mem mapping once per sample
        gpu_map = get_gpu_process_memory_map()

        # iterate processes
        current_pids = set()
        for p in safe_proc_iter(['pid','name']):
            pid = p.pid
            current_pids.add(pid)
            try:
                cpu = p.cpu_percent(interval=None)
            except Exception:
                cpu = 0.0
            try:
                mem = p.memory_percent()
            except Exception:
                mem = 0.0

            # IO counters and delta -> KB/s
            try:
                io = p.io_counters()
                read_bytes = io.read_bytes if io else 0
                write_bytes = io.write_bytes if io else 0
            except Exception:
                read_bytes = 0
                write_bytes = 0

            last = self._last_proc_io.get(pid)
            if last is None:
                read_kbs = 0.0
                write_kbs = 0.0
            else:
                elapsed = REFRESH_INTERVAL_MS / 1000.0
                try:
                    read_kbs = max(0.0, (read_bytes - last[0]) / elapsed / 1024.0)
                    write_kbs = max(0.0, (write_bytes - last[1]) / elapsed / 1024.0)
                except Exception:
                    read_kbs = 0.0
                    write_kbs = 0.0
            self._last_proc_io[pid] = (read_bytes, write_bytes)

            # connection count
            try:
                conns = p.connections(kind='inet')
                conn_count = len(conns)
            except Exception:
                conn_count = 0

            # GPU mem MB for pid
            gpu_mb = float(gpu_map.get(pid, 0.0))

            # append per-pid histories
            self.per_pid_cpu[pid].append(cpu)
            self.per_pid_mem[pid].append(mem)
            self.per_pid_gpu[pid].append(gpu_mb)
            self.per_pid_io_read[pid].append(read_kbs)
            self.per_pid_io_write[pid].append(write_kbs)
            self.per_pid_conns[pid].append(conn_count)

        # prune dead pids
        dead = set(self.per_pid_cpu.keys()) - current_pids
        for d in dead:
            try:
                del self.per_pid_cpu[d]
                del self.per_pid_mem[d]
                del self.per_pid_gpu[d]
                del self.per_pid_io_read[d]
                del self.per_pid_io_write[d]
                del self.per_pid_conns[d]
                self._last_proc_io.pop(d, None)
            except Exception:
                pass
        self.known_pids = current_pids

    # -------------------------
    # System plots update
    # -------------------------
    def _update_system_plots(self):
        self.sys_cpu_curve.setData(list(self.sys_cpu_hist))
        self.sys_mem_curve.setData(list(self.sys_mem_hist))
        if GPU_BACKEND:
            self.sys_gpu_curve.setData(list(self.sys_gpu_hist))
            self.sys_gpu_plot.show()
        else:
            self.sys_gpu_curve.setData([])
            self.sys_gpu_plot.setTitle("System GPU % (no GPU API detected)")

    # -------------------------
    # Process tree (safe) builder
    # -------------------------
    def _rebuild_tree(self):
        proc_info = {}
        children_map = defaultdict(list)
        for p in safe_proc_iter(['pid','name','ppid','cpu_percent','memory_percent']):
            try:
                info = p.info
            except Exception:
                continue
            pid = info.get('pid')
            proc_info[pid] = info
            ppid = info.get('ppid') or 0
            children_map[ppid].append(pid)

        self.tree.clear()
        visited = set()
        def make_item(pid):
            info = proc_info.get(pid, {})
            name = info.get('name') or ""
            cpu = info.get('cpu_percent', 0.0)
            mem = info.get('memory_percent', 0.0)
            item = QtWidgets.QTreeWidgetItem([str(pid), name, f"{cpu:.1f}", f"{mem:.1f}"])
            item.setData(0, QtCore.Qt.UserRole, pid)
            return item

        def add_children_safe(parent_item, pid):
            if pid in visited:
                return
            visited.add(pid)
            for child_pid in sorted(children_map.get(pid, [])):
                try:
                    if child_pid not in proc_info:
                        continue
                    child_item = make_item(child_pid)
                    parent_item.addChild(child_item)
                    add_children_safe(child_item, child_pid)
                except Exception:
                    continue

        root_pids = [pid for pid, info in proc_info.items() if (info.get('ppid') not in proc_info) or info.get('ppid') in (0, None)]
        for pid in sorted(root_pids):
            try:
                top = make_item(pid)
                self.tree.addTopLevelItem(top)
                add_children_safe(top, pid)
            except Exception:
                continue
        self.tree.expandToDepth(0)

    # -------------------------
    # Selection sync & details
    # -------------------------
    def on_table_doubleclick(self, index):
        pid = self.model.get_pid_at_row(index.row())
        if pid:
            self.fill_process_details(pid)
            self.select_pid_in_tree(pid)

    def on_table_selection_changed(self, selected, _deselected):
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
        it = QtWidgets.QTreeWidgetItemIterator(self.tree)
        while it.value():
            item = it.value()
            if item.data(0, QtCore.Qt.UserRole) == pid:
                self.tree.setCurrentItem(item)
                parent = item.parent()
                while parent:
                    parent.setExpanded(True)
                    parent = parent.parent()
                return
            it = it + 1

    def select_pid_in_table(self, pid):
        for row_idx, r in enumerate(self.model.process_rows):
            try:
                if int(r.get('pid')) == int(pid):
                    self.table.selectRow(row_idx)
                    self.table.scrollTo(self.model.index(row_idx, 0), QtWidgets.QAbstractItemView.PositionAtCenter)
                    return
            except Exception:
                continue

    def get_selected_pid(self):
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

        # instantaneous values from last-sampled histories
        read_kbs = None
        write_kbs = None
        gpu_mb = None
        conn_count = None
        try:
            if pid in self.per_pid_io_read and len(self.per_pid_io_read[pid])>0:
                read_kbs = self.per_pid_io_read[pid][-1]
            if pid in self.per_pid_io_write and len(self.per_pid_io_write[pid])>0:
                write_kbs = self.per_pid_io_write[pid][-1]
            if pid in self.per_pid_gpu and len(self.per_pid_gpu[pid])>0:
                gpu_mb = self.per_pid_gpu[pid][-1]
            if pid in self.per_pid_conns and len(self.per_pid_conns[pid])>0:
                conn_count = self.per_pid_conns[pid][-1]
        except Exception:
            pass

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
        if gpu_mb is None or gpu_mb == 0.0:
            if GPU_BACKEND:
                try:
                    lines.append(f"GPU mem: {gpu_mb:.1f} MB")
                except Exception:
                    lines.append("GPU mem: 0.0 MB")
            else:
                lines.append("GPU mem: N/A")
        else:
            lines.append(f"GPU mem: {gpu_mb:.1f} MB")
        if read_kbs is not None:
            lines.append(f"I/O read: {read_kbs:.2f} KB/s")
        else:
            lines.append("I/O read: N/A")
        if write_kbs is not None:
            lines.append(f"I/O write: {write_kbs:.2f} KB/s")
        else:
            lines.append("I/O write: N/A")
        if conn_count is not None:
            lines.append(f"Active connections: {int(conn_count)}")
        else:
            lines.append("Active connections: N/A")

        lines.append(f"Status: {info.get('status')}")
        lines.append(f"Threads: {info.get('num_threads')}")
        ppid = info.get('ppid')
        if ppid is not None:
            lines.append(f"Parent PID: {ppid}")
        io = info.get('io_counters')
        if io:
            lines.append(f"I/O - read total: {getattr(io,'read_bytes',None)} bytes, write total: {getattr(io,'write_bytes',None)} bytes")
        conns = info.get('connections')
        if conns:
            try:
                lines.append(f"Connections (snapshot): {len(conns)}")
            except Exception:
                pass
        self.detail_text.setPlainText("\n".join(lines))

    # -------------------------
    # Per-process plotting
    # -------------------------
    def update_per_process_plots(self, pid):
        cpu_series = list(self.per_pid_cpu.get(pid, []))
        mem_series = list(self.per_pid_mem.get(pid, []))
        gpu_series = list(self.per_pid_gpu.get(pid, []))
        io_r_series = list(self.per_pid_io_read.get(pid, []))
        io_w_series = list(self.per_pid_io_write.get(pid, []))
        conn_series = list(self.per_pid_conns.get(pid, []))

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

        if gpu_series and any(v > 0 for v in gpu_series):
            self.gpu_curve.setData(gpu_series)
            self.gpu_plot.setTitle(f"Process GPU Memory (MB) — PID {pid}")
        else:
            self.gpu_curve.setData(gpu_series)
            self.gpu_plot.setTitle(f"Process GPU Memory (MB) — PID {pid} (no data)")

        if io_r_series or io_w_series:
            self.io_read_curve.setData(io_r_series)
            self.io_write_curve.setData(io_w_series)
            self.io_plot.setTitle(f"Process Disk I/O KB/s — PID {pid}")
        else:
            self.io_read_curve.setData([])
            self.io_write_curve.setData([])
            self.io_plot.setTitle(f"Process Disk I/O KB/s — PID {pid} (no data)")

        if conn_series:
            self.conn_curve.setData(conn_series)
            self.conn_plot.setTitle(f"Process Active Connections — PID {pid}")
        else:
            self.conn_curve.setData([])
            self.conn_plot.setTitle(f"Process Active Connections — PID {pid} (no data)")

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
        self.refresh_all(force=True)

    def action_kill(self):
        pid = self.get_selected_pid()
        if pid:
            self._perform_kill(pid)
            self.refresh_all(force=True)

    def action_suspend(self):
        pid = self.get_selected_pid()
        if pid:
            self._perform_suspend(pid)
            self.refresh_all(force=True)

    def action_resume(self):
        pid = self.get_selected_pid()
        if pid:
            self._perform_resume(pid)
            self.refresh_all(force=True)

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
    # IMPORTANT: set High DPI attributes BEFORE creating QApplication
    try:
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)
    except Exception:
        pass

    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
