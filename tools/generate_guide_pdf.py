import os
import subprocess
import shutil
from pathlib import Path

def build_pdf():
    root = Path(__file__).resolve().parent.parent
    docs_dir = root / "docs"
    html_file = docs_dir / "SAST_ENGINE_MANUAL_GUIDE.html"
    pdf_docs_file = docs_dir / "SAST_ENGINE_MANUAL_GUIDE.pdf"
    pdf_root_file = root / "SAST_ENGINE_MANUAL_GUIDE.pdf"
    
    if not html_file.exists():
        raise FileNotFoundError(f"HTML guide not found at {html_file}")
    
    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    edge_exe = next((p for p in edge_paths if os.path.exists(p)), None)
    if not edge_exe:
        raise RuntimeError("Microsoft Edge executable not found.")
    
    cmd = [
        edge_exe,
        "--headless",
        "--disable-gpu",
        "--run-all-compositor-stages-before-draw",
        "--no-pdf-header-footer",
        f"--print-to-pdf={pdf_docs_file.resolve()}",
        html_file.resolve().as_uri()
    ]
    
    subprocess.run(cmd, check=True)
    shutil.copy2(pdf_docs_file, pdf_root_file)
    print(f"PDF generated successfully:")
    print(f"  1. {pdf_root_file}")
    print(f"  2. {pdf_docs_file}")

if __name__ == "__main__":
    build_pdf()
