from PyQt6.QtCore import QThread, pyqtSignal
import subprocess

class VolatilityWorker(QThread):
    output_received = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    analysis_finished = pyqtSignal()
    progress_update = pyqtSignal(str)

    def __init__(self, command, cwd):
        super().__init__()
        self.command = command
        self.cwd = cwd
        self._is_running = True

    def run(self):
        try:
            process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.cwd,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            output_lines = []
            while self._is_running:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output and not any(word in output.lower() for word in ["loading", "progress", "processing"]):
                    output_lines.append(output.strip())

            self.output_received.emit("\n".join(output_lines))

            stderr = process.stderr.read()
            process.wait()

            if process.returncode != 0:
                error_msg = ""
                if stderr:
                    for line in stderr.splitlines():
                        lower_line = line.lower()
                        if not any(word in lower_line for word in [
                            "progress", "scanning", "scanner", "stacking", "using", "finished", "attempts",
                            "memory_layer", "filelayer", "bytestream", "warning", "userwarning"
                        ]):
                            error_msg += line + "\n"
                if error_msg.strip():
                    self.error_occurred.emit(error_msg.strip())
                else:
                    self.error_occurred.emit("El comando finalizó con error desconocido.")
            else:
                if stderr:
                    for line in stderr.splitlines():
                        lower_line = line.lower()
                        if any(word in lower_line for word in [
                            "progress", "scanning", "scanner", "stacking", "using", "finished", "attempts",
                            "memory_layer", "filelayer", "bytestream", "warning", "userwarning"
                        ]):
                            self.progress_update.emit(line)

            self.analysis_finished.emit()

        except Exception as e:
            self.error_occurred.emit(str(e))

    def stop(self):
        self._is_running = False
        self.terminate()
