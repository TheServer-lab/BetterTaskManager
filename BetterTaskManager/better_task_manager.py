# better_task_manager.py
import sys
import psutil
from PyQt5 import QtWidgets, QtCore, QtGui
import pyqtgraph as pg
import datetime

REFRESH_INTERVAL_MS = 1500

class ProcessTableModel(QtCore.QAbstractTableModel):
    HEADERS = ["PID", "Name", "CPU %", "Memory %", "Status", "User", "Cmdline"]
    def __init__(self, parent=None):
        super().__init__(parent)
        self.process_rows = []
        self.update_snapshot()

    def update_snapshot(self, filter_text=""):
        procs = []
        for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent','status','username','cmdline']):
            try:
                info = p.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if filter_text:
                ft = filter_text.lower()
                if ft not in (str(info.get('pid','')).lower() + " " + (info.get('name') or "").lower() + " " + " ".join(info.get('cmdline') or []).lower()):
                    continue
            procs.append(info)
        # sort: CPU desc then name
        procs.sort(key=lambda x: (-x.get('cpu_percent',0), str(x.get('name',''))))
        self.beginResetModel()
        self.process_rows = procs
        self.endResetModel()

    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self.process_rows)

    def columnCount(self, parent=QtCore.QModelIndex()):
        return len(self.HEADERS)

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid(): return None
        row = self.process_rows[index.row()]
        col = index.column()
        if role == QtCore.Qt.DisplayRole:
            if col == 0: return str(row.get('pid',''))
            if col == 1: return row.get('name','')
            if col == 2: return f"{row.get('cpu_percent',0):.1f}"
            if col == 3: return f"{row.get('memory_percent',0):.1f}"
            if col == 4: return row.get('status','')
            if col == 5: return row.get('username','')
            if col == 6:
                cmd = row.get('cmdline') or []
                return " ".join(cmd)[:200]
        if role == QtCore.Qt.TextAlignmentRole:
            if col in (0,2,3): return QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter
        return None

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role != QtCore.Qt.DisplayRole: return None
        if orientation == QtCore.Qt.Horizontal:
            return self.HEADERS[section]
        return int(section+1)

    def get_pid_at_row(self, row):
        try:
            return int(self.process_rows[row]['pid'])
        except:
            return None

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Better Task Manager (Prototype)")
        self.resize(1000, 700)

        # central widget layout
        w = QtWidgets.QWidget()
        vbox = QtWidgets.QVBoxLayout()
        w.setLayout(vbox)
        self.setCentralWidget(w)

        # top: search + controls
        top_h = QtWidgets.QHBoxLayout()
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText("Search PID / name / cmdline ...")
        self.search.returnPressed.connect(self.manual_refresh)
        btn_refresh = QtWidgets.QPushButton("Refresh")
        btn_refresh.clicked.connect(self.manual_refresh)
        top_h.addWidget(self.search)
        top_h.addWidget(btn_refresh)
        vbox.addLayout(top_h)

        # middle: table + details
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        vbox.addWidget(splitter, 1)

        # table
        self.model = ProcessTableModel()
        self.table = QtWidgets.QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QtWidgets.QTableView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QTableView.SingleSelection)
        self.table.doubleClicked.connect(self.show_process_details)
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.table_context_menu)
        self.table.setSortingEnabled(True)
        splitter.addWidget(self.table)

        # right: details + graphs
        right = QtWidgets.QWidget()
        rv = QtWidgets.QVBoxLayout()
        right.setLayout(rv)
        # details
        self.detail_text = QtWidgets.QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFixedHeight(180)
        rv.addWidget(self.detail_text)
        # graphs
        self.cpu_plot = pg.PlotWidget(title="CPU (%)")
        self.mem_plot = pg.PlotWidget(title="Memory (%)")
        self.cpu_plot.setYRange(0, 100)
        self.mem_plot.setYRange(0, 100)
        rv.addWidget(self.cpu_plot, 1)
        rv.addWidget(self.mem_plot, 1)
        splitter.addWidget(right)

        # bottom: action buttons
        h = QtWidgets.QHBoxLayout()
        btn_kill = QtWidgets.QPushButton("Kill")
        btn_suspend = QtWidgets.QPushButton("Suspend")
        btn_resume = QtWidgets.QPushButton("Resume")
        btn_setprio = QtWidgets.QPushButton("Set Priority (low/normal/high)")
        btn_kill.clicked.connect(self.action_kill)
        btn_suspend.clicked.connect(self.action_suspend)
        btn_resume.clicked.connect(self.action_resume)
        btn_setprio.clicked.connect(self.action_set_priority)
        h.addWidget(btn_kill)
        h.addWidget(btn_suspend)
        h.addWidget(btn_resume)
        h.addWidget(btn_setprio)
        h.addStretch()
        vbox.addLayout(h)

        # data for graphs
        self.cpu_history = []
        self.mem_history = []
        self.max_points = 120

        # plots
        self.cpu_curve = self.cpu_plot.plot()
        self.mem_curve = self.mem_plot.plot()

        # timer
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(REFRESH_INTERVAL_MS)

        # initial refresh
        self.refresh()

    def manual_refresh(self):
        self.refresh(force=True)

    def refresh(self, force=False):
        filter_text = self.search.text().strip()
        self.model.update_snapshot(filter_text)
        # update details area for selected row
        sel = self.table.selectionModel().selectedRows()
        if sel:
            pid = self.model.get_pid_at_row(sel[0].row())
            self.fill_process_details(pid)
        else:
            self.detail_text.setPlainText("Select a process to see details.")
        # system usage
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        self._append_history(cpu, mem)
        self.cpu_curve.setData(self.cpu_history)
        self.mem_curve.setData(self.mem_history)

    def _append_history(self, cpu, mem):
        self.cpu_history.append(cpu)
        self.mem_history.append(mem)
        if len(self.cpu_history) > self.max_points:
            self.cpu_history.pop(0)
            self.mem_history.pop(0)

    def get_selected_pid(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            QtWidgets.QMessageBox.information(self, "No selection", "Please select a process row first.")
            return None
        return self.model.get_pid_at_row(sel[0].row())

    def action_kill(self):
        pid = self.get_selected_pid()
        if not pid: return
        try:
            p = psutil.Process(pid)
            p.kill()
            QtWidgets.QMessageBox.information(self, "Killed", f"Process {pid} killed.")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Failed to kill {pid}:\n{e}")
        self.refresh(force=True)

    def action_suspend(self):
        pid = self.get_selected_pid()
        if not pid: return
        try:
            p = psutil.Process(pid)
            p.suspend()
            QtWidgets.QMessageBox.information(self, "Suspended", f"Process {pid} suspended.")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Failed to suspend {pid}:\n{e}")
        self.refresh(force=True)

    def action_resume(self):
        pid = self.get_selected_pid()
        if not pid: return
        try:
            p = psutil.Process(pid)
            p.resume()
            QtWidgets.QMessageBox.information(self, "Resumed", f"Process {pid} resumed.")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Failed to resume {pid}:\n{e}")
        self.refresh(force=True)

    def action_set_priority(self):
        pid = self.get_selected_pid()
        if not pid: return
        levels = {"low": psutil.IDLE_PRIORITY_CLASS if hasattr(psutil, 'IDLE_PRIORITY_CLASS') else 19,
                  "normal": psutil.NORMAL_PRIORITY_CLASS if hasattr(psutil, 'NORMAL_PRIORITY_CLASS') else 0,
                  "high": psutil.HIGH_PRIORITY_CLASS if hasattr(psutil, 'HIGH_PRIORITY_CLASS') else -20}
        choice, ok = QtWidgets.QInputDialog.getItem(self, "Set Priority", "Select priority:", ["low","normal","high"], 1, False)
        if not ok: return
        try:
            p = psutil.Process(pid)
            p.nice(levels[choice])
            QtWidgets.QMessageBox.information(self, "Priority", f"Set priority of {pid} to {choice}.")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Failed to set priority for {pid}:\n{e}")
        self.refresh(force=True)

    def show_process_details(self, index):
        pid = self.model.get_pid_at_row(index.row())
        self.fill_process_details(pid)

    def fill_process_details(self, pid):
        if pid is None:
            self.detail_text.setPlainText("No details.")
            return
        try:
            p = psutil.Process(pid)
            info = p.as_dict(attrs=['pid','name','exe','cmdline','username','create_time','cpu_percent','memory_percent','status','num_threads','io_counters','connections'])
        except psutil.NoSuchProcess:
            self.detail_text.setPlainText("Process no longer exists.")
            return
        txt = []
        txt.append(f"PID: {info.get('pid')}")
        txt.append(f"Name: {info.get('name')}")
        txt.append(f"Executable: {info.get('exe')}")
        txt.append(f"Cmdline: {' '.join(info.get('cmdline') or [])}")
        txt.append(f"User: {info.get('username')}")
        ct = info.get('create_time')
        if ct:
            txt.append("Started: " + datetime.datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S"))
        txt.append(f"CPU %: {info.get('cpu_percent')}")
        txt.append(f"Memory %: {info.get('memory_percent')}")
        txt.append(f"Status: {info.get('status')}")
        txt.append(f"Threads: {info.get('num_threads')}")
        io = info.get('io_counters')
        if io:
            txt.append(f"I/O - read: {getattr(io,'read_bytes',None)} bytes, write: {getattr(io,'write_bytes',None)} bytes")
        conns = info.get('connections')
        if conns:
            txt.append(f"Connections: {len(conns)}")
        self.detail_text.setPlainText("\n".join(txt))

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
        act_open_folder = menu.addAction("Open executable folder")
        action = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if action == act_kill:
            try: psutil.Process(pid).kill()
            except Exception as e: QtWidgets.QMessageBox.warning(self, "Error", str(e))
            self.refresh()
        elif action == act_suspend:
            try: psutil.Process(pid).suspend()
            except Exception as e: QtWidgets.QMessageBox.warning(self, "Error", str(e))
            self.refresh()
        elif action == act_resume:
            try: psutil.Process(pid).resume()
            except Exception as e: QtWidgets.QMessageBox.warning(self, "Error", str(e))
            self.refresh()
        elif action == act_details:
            self.fill_process_details(pid)
        elif action == act_open_folder:
            try:
                p = psutil.Process(pid)
                exe = p.exe()
                import os, subprocess
                folder = os.path.dirname(exe)
                if sys.platform.startswith('win'):
                    subprocess.Popen(['explorer', folder])
                elif sys.platform.startswith('linux'):
                    subprocess.Popen(['xdg-open', folder])
                elif sys.platform.startswith('darwin'):
                    subprocess.Popen(['open', folder])
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "Error", f"Could not open folder: {e}")

def main():
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
