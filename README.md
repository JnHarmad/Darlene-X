ForensiPie- Android Static Analysis Tool

<img width="1518" height="494" alt="Screenshot (181)" src="https://github.com/user-attachments/assets/f7d22ff5-bf8c-412b-865f-396be42325f0" />



To run this forensipie_cli.py module from windows powershell, these are steps:
cd <path/forensipie/localsystem>
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
venv\Scripts\activate
python -m forensipie.forensipie_cli

Technical dependencies, that need to be downloaded, are not documented yet.

Author is reviewing logics of every module, train the framework with malware samples to reduce false positives.
New parameter- Native Code Analysis will be in framework soon.
