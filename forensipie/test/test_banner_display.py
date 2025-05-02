# test_banner_display.py

import time
from forensipie.modules.banner_display import show_banner

def test_show_banner():
    print("\n[TEST] Running banner display test...\n")
    show_banner()
    time.sleep(2)  # Allow time to visually confirm banner display
    print("\n[TEST] Banner display test completed.\n")

if __name__ == "__main__":
    test_show_banner()
