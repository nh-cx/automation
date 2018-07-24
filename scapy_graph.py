# #!/usr/bin/python3.6
# # -*- coding=utf-8 -*-
# # 学习专用
# # ======程序说明======
# #
# #
# # ==================
import os
import sys
import time
import subprocess
import warnings
import logging
warnings.filterwarnings("ignore", category=DeprecationWarning)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import traceroute

res, unans = traceroute(["baidu.com"])
res.graph(target="test.svg")
print("ok!")


# if __name__ == "__main__":
