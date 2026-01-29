import subprocess

cmd = [
    "gcc",
    "main.c",
    "-o",
    "loadll.exe",
    "-O3",
    "-s",
    "-flto",
    "-static",
    "-march=native",
    "-mtune=native",
    "-Wl,--gc-sections",
    "-fdata-sections",
    "-ffunction-sections",
]

try:
    subprocess.run(cmd, check=True)
    print("Done.")
except subprocess.CalledProcessError as e:
    print(e)
