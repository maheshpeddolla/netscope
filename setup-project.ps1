# =====================================================================
# NetScope Project Bootstrap Script
# Version: 0.1
# Creates project folders and empty files
# =====================================================================

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "     NetScope Project Bootstrap"
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------
# Folder Structure
# ---------------------------------------------------------------------

$folders = @(

    "docs",
    "tests",
    "scripts",
    "examples",
    "output",

    "netscope",

    "netscope\collectors",
    "netscope\monitors",
    "netscope\parsers",
    "netscope\engines",
    "netscope\reports",
    "netscope\utils",
    "netscope\plugins",

    "netscope\plugins\rhel",
    "netscope\plugins\sles",
    "netscope\plugins\ubuntu"
)

foreach ($folder in $folders) {
    New-Item -ItemType Directory -Force -Path $folder | Out-Null
}

# ---------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------

$files = @(

    ".gitignore",
    "README.md",
    "LICENSE",
    "requirements.txt",
    "pyproject.toml",

    "docs\architecture.md",
    "docs\roadmap.md",

    "netscope\__init__.py",
    "netscope\cli.py",
    "netscope\config.py",
    "netscope\logger.py",
    "netscope\version.py",

    # -----------------------------
    # Collectors
    # -----------------------------

    "netscope\collectors\__init__.py",
    "netscope\collectors\system.py",
    "netscope\collectors\network.py",
    "netscope\collectors\driver.py",
    "netscope\collectors\tcp.py",
    "netscope\collectors\kernel.py",
    "netscope\collectors\azure.py",
    "netscope\collectors\firewall.py",
    "netscope\collectors\performance.py",

    # -----------------------------
    # Monitors
    # -----------------------------

    "netscope\monitors\__init__.py",
    "netscope\monitors\softnet.py",
    "netscope\monitors\nic.py",
    "netscope\monitors\packetdrop.py",
    "netscope\monitors\journal.py",
    "netscope\monitors\tcp.py",
    "netscope\monitors\metadata.py",

    # -----------------------------
    # Parsers
    # -----------------------------

    "netscope\parsers\__init__.py",
    "netscope\parsers\sosreport.py",
    "netscope\parsers\journal.py",
    "netscope\parsers\ethtool.py",

    # -----------------------------
    # Engines
    # -----------------------------

    "netscope\engines\__init__.py",
    "netscope\engines\rule_engine.py",
    "netscope\engines\correlation_engine.py",
    "netscope\engines\ai_engine.py",

    # -----------------------------
    # Reports
    # -----------------------------

    "netscope\reports\__init__.py",
    "netscope\reports\html.py",
    "netscope\reports\json.py",
    "netscope\reports\terminal.py",

    # -----------------------------
    # Utils
    # -----------------------------

    "netscope\utils\__init__.py",
    "netscope\utils\command.py",
    "netscope\utils\distro.py",
    "netscope\utils\logger.py",
    "netscope\utils\helpers.py",

    # -----------------------------
    # Plugins - RHEL
    # -----------------------------

    "netscope\plugins\__init__.py",

    "netscope\plugins\rhel\__init__.py",
    "netscope\plugins\rhel\network.py",
    "netscope\plugins\rhel\system.py",

    # -----------------------------
    # Plugins - SLES
    # -----------------------------

    "netscope\plugins\sles\__init__.py",
    "netscope\plugins\sles\network.py",
    "netscope\plugins\sles\system.py",

    # -----------------------------
    # Plugins - Ubuntu
    # -----------------------------

    "netscope\plugins\ubuntu\__init__.py",
    "netscope\plugins\ubuntu\network.py",
    "netscope\plugins\ubuntu\system.py"
)

foreach ($file in $files) {

    if (!(Test-Path $file)) {

        New-Item -ItemType File -Path $file | Out-Null

    }

}

Write-Host ""
Write-Host "Project structure created successfully!" -ForegroundColor Green
Write-Host ""

tree /F