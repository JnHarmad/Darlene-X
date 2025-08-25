ForensiPie- Android Malware Analysis Tool


To run this forensipie_cli.py module from windows powershell, these are steps:
cd <path/forensipie/localsystem>
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
venv\Scripts\activate
python -m forensipie.forensipie_cli

Technical dependencies, that need to be downloaded, are not documented yet.

Author is reviewing logics of every module, train the framework with malware samples to reduce false positives.
New parameter- Native Code Analysis will be in framework soon.
